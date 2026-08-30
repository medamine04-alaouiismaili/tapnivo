export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // =====================================================
    // HELPERS
    // =====================================================

    const json = (data, status = 200, extraHeaders = {}) => {
      return new Response(JSON.stringify(data), {
        status,
        headers: {
          "Content-Type": "application/json; charset=UTF-8",
          ...extraHeaders
        }
      });
    };

    const base64url = (input) => {
      let binary = "";

      if (input instanceof Uint8Array) {
        for (const byte of input) {
          binary += String.fromCharCode(byte);
        }
      } else {
        binary = input;
      }

      return btoa(binary)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
    };

    const fromBase64url = (input) => {
      const base64 =
        input.replace(/-/g, "+").replace(/_/g, "/") +
        "===".slice((input.length + 3) % 4);

      const binary = atob(base64);

      const bytes = new Uint8Array(binary.length);

      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }

      return bytes;
    };

    const timingSafeEqual = (a, b) => {
      if (a.length !== b.length) {
        return false;
      }

      let result = 0;

      for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];
      }

      return result === 0;
    };

    const escapeHTML = (value) => {
      if (value === null || value === undefined) {
        return "";
      }

      return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    };

    const generateServiceCode = () => {
      return (
        "SVC-" +
        crypto.randomUUID()
          .replace(/-/g, "")
          .slice(0, 12)
          .toUpperCase()
      );
    };

    // =====================================================
    // ADMIN SESSION
    // =====================================================

    const createAdminToken = async () => {
      if (!env.ADMIN_KEY) {
        throw new Error("ADMIN_KEY non configurée.");
      }

      const timestamp = Date.now().toString();
      const encoder = new TextEncoder();

      const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(env.ADMIN_KEY),
        {
          name: "HMAC",
          hash: "SHA-256"
        },
        false,
        ["sign"]
      );

      const signature = new Uint8Array(
        await crypto.subtle.sign(
          "HMAC",
          key,
          encoder.encode(timestamp)
        )
      );

      return (
        base64url(timestamp) +
        "." +
        base64url(signature)
      );
    };

    const verifyAdminToken = async (token) => {
      if (!token || !env.ADMIN_KEY) {
        return false;
      }

      const parts = token.split(".");

      if (parts.length !== 2) {
        return false;
      }

      try {
        const timestampBytes =
          fromBase64url(parts[0]);

        const timestamp =
          new TextDecoder().decode(timestampBytes);

        const time = Number(timestamp);

        if (!Number.isFinite(time)) {
          return false;
        }

        if (
          Date.now() - time >
          8 * 60 * 60 * 1000
        ) {
          return false;
        }

        if (time > Date.now() + 60000) {
          return false;
        }

        const encoder = new TextEncoder();

        const key =
          await crypto.subtle.importKey(
            "raw",
            encoder.encode(env.ADMIN_KEY),
            {
              name: "HMAC",
              hash: "SHA-256"
            },
            false,
            ["sign"]
          );

        const expected =
          new Uint8Array(
            await crypto.subtle.sign(
              "HMAC",
              key,
              encoder.encode(timestamp)
            )
          );

        const received =
          fromBase64url(parts[1]);

        return timingSafeEqual(
          expected,
          received
        );

      } catch {
        return false;
      }
    };

    const getCookie = (request, name) => {
      const cookieHeader =
        request.headers.get("Cookie");

      if (!cookieHeader) {
        return null;
      }

      const cookies =
        cookieHeader.split(";");

      for (const cookie of cookies) {
        const parts =
          cookie.trim().split("=");

        if (parts[0] === name) {
          return parts.slice(1).join("=");
        }
      }

      return null;
    };

    const isAdmin = async () => {
      const token =
        getCookie(
          request,
          "tapnivo_admin"
        );

      return await verifyAdminToken(token);
    };

    // =====================================================
    // ADMIN LOGIN
    // =====================================================

    if (
      url.pathname === "/api/admin/login" &&
      request.method === "POST"
    ) {
      try {
        const data =
          await request.json();

        const password =
          String(data.password || "");

        if (!env.ADMIN_KEY) {
          return json(
            {
              success: false,
              error:
                "ADMIN_KEY non configurée."
            },
            500
          );
        }

        if (
          !password ||
          password !== env.ADMIN_KEY
        ) {
          return json(
            {
              success: false,
              error:
                "Mot de passe incorrect."
            },
            401
          );
        }

        const token =
          await createAdminToken();

        return json(
          {
            success: true,
            message:
              "Connexion administrateur réussie."
          },
          200,
          {
            "Set-Cookie":
              `tapnivo_admin=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`
          }
        );

      } catch (error) {
        return json(
          {
            success: false,
            error: error.message
          },
          500
        );
      }
    }

    // =====================================================
    // ADMIN CHECK
    // =====================================================

    if (
      url.pathname === "/api/admin/me" &&
      request.method === "GET"
    ) {
      const authenticated =
        await isAdmin();

      return json({
        success: true,
        authenticated
      });
    }

    // =====================================================
    // ADMIN LOGOUT
    // =====================================================

    if (
      url.pathname === "/api/admin/logout" &&
      request.method === "POST"
    ) {
      return json(
        {
          success: true
        },
        200,
        {
          "Set-Cookie":
            "tapnivo_admin=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
        }
      );
    }

    // =====================================================
    // TEST DATABASE
    // =====================================================

    if (
      url.pathname === "/api/test-db"
    ) {
      try {
        const result =
          await env.DB
            .prepare(
              "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            .all();

        return json({
          success: true,
          database: "tapnivo-db",
          tables: result.results
        });

      } catch (error) {
        return json(
          {
            success: false,
            error: error.message
          },
          500
        );
      }
    }

    // =====================================================
    // GET ALL CLIENTS
    // =====================================================

    if (
      url.pathname === "/api/clients" &&
      request.method === "GET"
    ) {
      try {
        const result =
          await env.DB
            .prepare(
              "SELECT * FROM clients ORDER BY id DESC"
            )
            .all();

        return json({
          success: true,
          clients: result.results
        });

      } catch (error) {
        return json(
          {
            success: false,
            error: error.message
          },
          500
        );
      }
    }

    // =====================================================
    // CREATE CLIENT
    // =====================================================

    if (
      url.pathname === "/api/clients" &&
      request.method === "POST"
    ) {
      try {
        if (!(await isAdmin())) {
          return json(
            {
              success: false,
              error: "Non autorisé."
            },
            401
          );
        }

        const data =
          await request.json();

        if (!data.name) {
          return json(
            {
              success: false,
              error:
                "Le nom du client est obligatoire."
            },
            400
          );
        }

        const slug =
          data.slug ||
          data.name
            .toLowerCase()
            .normalize("NFD")
            .replace(/[\u0300-\u036f]/g, "")
            .replace(/[^a-z0-9]+/g, "-")
            .replace(/^-|-$/g, "") +
          "-" +
          Date.now();

        await env.DB
          .prepare(`
            INSERT INTO clients (
              name,
              profession,
              bio,
              phone,
              whatsapp,
              email,
              instagram,
              facebook,
              tiktok,
              linkedin,
              address,
              maps,
              website,
              reviews,
              photo_url,
              slug
            )
            VALUES (
              ?, ?, ?, ?, ?,
              ?, ?, ?, ?, ?,
              ?, ?, ?, ?, ?, ?
            )
          `)
          .bind(
            data.name || null,
            data.profession || null,
            data.bio || null,
            data.phone || null,
            data.whatsapp || null,
            data.email || null,
            data.instagram || null,
            data.facebook || null,
            data.tiktok || null,
            data.linkedin || null,
            data.address || null,
            data.maps || null,
            data.website || null,
            data.reviews || null,
            data.photo_url || null,
            slug
          )
          .run();

        return json({
          success: true,
          message:
            "Client créé avec succès.",
          slug
        });

      } catch (error) {
        return json(
          {
            success: false,
            error: error.message
          },
          500
        );
      }
    }

    // =====================================================
    // =====================================================
    // SERVICES SYSTEM
    // =====================================================
    // =====================================================


    // =====================================================
    // GET ALL SERVICES
    // =====================================================

    if (
      url.pathname === "/api/services" &&
      request.method === "GET"
    ) {
      if (!(await isAdmin())) {
        return json(
          {
            success: false,
            error: "Non autorisé."
          },
          401
        );
      }

      try {
        const result =
          await env.DB
            .prepare(`
              SELECT
                s.id,
                s.client_id,
                s.service_type,
                s.service_name,
                s.status,
                s.service_code,
                s.destination_url,
                s.stand_id,
                s.config,
                s.created_at,
                s.activated_at,
                s.updated_at,

                c.name AS client_name,

                st.stand_code,

                (
                  SELECT COUNT(*)
                  FROM service_scans ss
                  WHERE ss.service_id = s.id
                ) AS scans_count,

                (
                  SELECT COUNT(*)
                  FROM service_scans ss
                  WHERE
                    ss.service_id = s.id
                    AND date(ss.scanned_at)
                      = date('now')
                ) AS scans_today,

                (
                  SELECT COUNT(*)
                  FROM service_scans ss
                  WHERE
                    ss.service_id = s.id
                    AND ss.scanned_at >= datetime(
                      'now',
                      '-7 days'
                    )
                ) AS scans_7_days,

                (
                  SELECT COUNT(*)
                  FROM service_scans ss
                  WHERE
                    ss.service_id = s.id
                    AND ss.scanned_at >= datetime(
                      'now',
                      '-30 days'
                    )
                ) AS scans_30_days,

                (
                  SELECT MAX(ss.scanned_at)
                  FROM service_scans ss
                  WHERE ss.service_id = s.id
                ) AS last_scan

              FROM services s

              LEFT JOIN clients c
                ON s.client_id = c.id

              LEFT JOIN stands st
                ON s.stand_id = st.id

              ORDER BY s.id DESC
            `)
            .all();

        return json({
          success: true,
          services: result.results
        });

      } catch (error) {
        return json(
          {
            success: false,
            error: error.message
          },
          500
        );
      }
    }


    // =====================================================
    // GET SERVICES FOR ONE CLIENT
    // =====================================================

    if (
      url.pathname.match(
        /^\/api\/clients\/\d+\/services$/
      ) &&
      request.method === "GET"
    ) {
      if (!(await isAdmin())) {
        return json(
          {
            success: false,
            error: "Non autorisé."
          },
          401
        );
      }

      try {
        const clientId =
          Number(
            url.pathname
              .split("/")[3]
          );

        const client =
          await env.DB
            .prepare(`
              SELECT id, name
              FROM clients
              WHERE id = ?
              LIMIT 1
            `)
            .bind(clientId)
            .first();

        if (!client) {
          return json(
            {
              success: false,
              error:
                "Client introuvable."
            },
            404
          );
        }

        const result =
          await env.DB
            .prepare(`
              SELECT
                s.*,

                (
                  SELECT COUNT(*)
                  FROM service_scans ss
                  WHERE ss.service_id = s.id
                ) AS scans_count,

                (
                  SELECT COUNT(*)
                  FROM service_scans ss
                  WHERE
                    ss.service_id = s.id
                    AND date(ss.scanned_at)
                      = date('now')
                ) AS scans_today,

                (
                  SELECT COUNT(*)
                  FROM service_scans ss
                  WHERE
                    ss.service_id = s.id
                    AND ss.scanned_at >= datetime(
                      'now',
                      '-7 days'
                    )
                ) AS scans_7_days,

                (
                  SELECT COUNT(*)
                  FROM service_scans ss
                  WHERE
                    ss.service_id = s.id
                    AND ss.scanned_at >= datetime(
                      'now',
                      '-30 days'
                    )
                ) AS scans_30_days,

                (
                  SELECT MAX(ss.scanned_at)
                  FROM service_scans ss
                  WHERE ss.service_id = s.id
                ) AS last_scan

              FROM services s

              WHERE s.client_id = ?

              ORDER BY s.id DESC
            `)
            .bind(clientId)
            .all();

        return json({
          success: true,
          client,
          services: result.results
        });

      } catch (error) {
        return json(
          {
            success: false,
            error: error.message
          },
          500
        );
      }
    }


    // =====================================================
    // CREATE SERVICE
    // =====================================================

    if (
      url.pathname === "/api/services" &&
      request.method === "POST"
    ) {
      if (!(await isAdmin())) {
        return json(
          {
            success: false,
            error: "Non autorisé."
          },
          401
        );
      }

      try {
        const data =
          await request.json();

        const clientId =
          Number(data.client_id);

        if (
          !clientId ||
          !Number.isInteger(clientId)
        ) {
          return json(
            {
              success: false,
              error:
                "client_id est obligatoire."
            },
            400
          );
        }

        const client =
          await env.DB
            .prepare(`
              SELECT id, name
              FROM clients
              WHERE id = ?
              LIMIT 1
            `)
            .bind(clientId)
            .first();

        if (!client) {
          return json(
            {
              success: false,
              error:
                "Client introuvable."
            },
            404
          );
        }

        const allowedTypes = [
          "google_review",
          "wifi",
          "menu",
          "digital_card",
          "custom_link"
        ];

        const serviceType =
          String(
            data.service_type || ""
          ).trim();

        if (
          !allowedTypes.includes(
            serviceType
          )
        ) {
          return json(
            {
              success: false,
              error:
                "Type de service invalide.",
              allowed_types:
                allowedTypes
            },
            400
          );
        }

        const defaultNames = {
          google_review:
            "Google Review",
          wifi:
            "Wi-Fi",
          menu:
            "Menu",
          digital_card:
            "Digital Business Card",
          custom_link:
            "Lien personnalisé"
        };

        const serviceName =
          String(
            data.service_name ||
            defaultNames[serviceType]
          ).trim();

        let destinationUrl =
          data.destination_url
            ? String(
                data.destination_url
              ).trim()
            : null;

        if (destinationUrl) {
          try {
            const parsed =
              new URL(destinationUrl);

            if (
              parsed.protocol !==
                "https:" &&
              parsed.protocol !==
                "http:"
            ) {
              return json(
                {
                  success: false,
                  error:
                    "URL HTTP/HTTPS uniquement."
                },
                400
              );
            }

          } catch {
            return json(
              {
                success: false,
                error:
                  "URL invalide."
              },
              400
            );
          }
        }

        let standId = null;

        if (
          data.stand_id !== null &&
          data.stand_id !== undefined &&
          data.stand_id !== ""
        ) {
          standId =
            Number(data.stand_id);

          if (
            !Number.isInteger(
              standId
            )
          ) {
            return json(
              {
                success: false,
                error:
                  "stand_id invalide."
              },
              400
            );
          }

          const stand =
            await env.DB
              .prepare(`
                SELECT id, stand_code
                FROM stands
                WHERE id = ?
                LIMIT 1
              `)
              .bind(standId)
              .first();

          if (!stand) {
            return json(
              {
                success: false,
                error:
                  "Stand introuvable."
              },
              404
            );
          }
        }

        let config = null;

        if (
          data.config !== undefined &&
          data.config !== null
        ) {
          if (
            typeof data.config ===
            "string"
          ) {
            try {
              JSON.parse(
                data.config
              );

              config =
                data.config;

            } catch {
              return json(
                {
                  success: false,
                  error:
                    "config JSON invalide."
                },
                400
              );
            }

          } else {
            config =
              JSON.stringify(
                data.config
              );
          }
        }

        const serviceCode =
          generateServiceCode();

        const status =
          data.status === "active"
            ? "active"
            : "draft";

        const activatedAt =
          status === "active"
            ? "CURRENT_TIMESTAMP"
            : null;

        if (
          status === "active" &&
          !destinationUrl
        ) {
          return json(
            {
              success: false,
              error:
                "Une destination URL est obligatoire pour activer le service."
            },
            400
          );
        }

        if (status === "active") {

          await env.DB
            .prepare(`
              INSERT INTO services (
                client_id,
                service_type,
                service_name,
                status,
                service_code,
                destination_url,
                stand_id,
                config,
                activated_at,
                updated_at
              )
              VALUES (
                ?, ?, ?, ?, ?,
                ?, ?, ?,
                CURRENT_TIMESTAMP,
                CURRENT_TIMESTAMP
              )
            `)
            .bind(
              clientId,
              serviceType,
              serviceName,
              status,
              serviceCode,
              destinationUrl,
              standId,
              config
            )
            .run();

        } else {

          await env.DB
            .prepare(`
              INSERT INTO services (
                client_id,
                service_type,
                service_name,
                status,
                service_code,
                destination_url,
                stand_id,
                config,
                updated_at
              )
              VALUES (
                ?, ?, ?, ?, ?,
                ?, ?, ?, CURRENT_TIMESTAMP
              )
            `)
            .bind(
              clientId,
              serviceType,
              serviceName,
              status,
              serviceCode,
              destinationUrl,
              standId,
              config
            )
            .run();

        }

        const created =
          await env.DB
            .prepare(`
              SELECT *
              FROM services
              WHERE service_code = ?
              LIMIT 1
            `)
            .bind(serviceCode)
            .first();

        return json({
          success: true,
          message:
            "Service créé avec succès.",
          service: created,
          dynamic_url:
            `${url.origin}/s/${serviceCode}`
        });

      } catch (error) {
        return json(
          {
            success: false,
            error: error.message
          },
          500
        );
      }
    }


    // =====================================================
    // UPDATE SERVICE
    // =====================================================

    if (
      url.pathname.match(
        /^\/api\/services\/\d+$/
      ) &&
      request.method === "PATCH"
    ) {
      if (!(await isAdmin())) {
        return json(
          {
            success: false,
            error: "Non autorisé."
          },
          401
        );
      }

      try {
        const serviceId =
          Number(
            url.pathname
              .split("/")[3]
          );

        const existing =
          await env.DB
            .prepare(`
              SELECT *
              FROM services
              WHERE id = ?
              LIMIT 1
            `)
            .bind(serviceId)
            .first();

        if (!existing) {
          return json(
            {
              success: false,
              error:
                "Service introuvable."
            },
            404
          );
        }

        const data =
          await request.json();

        const serviceName =
          data.service_name !==
          undefined
            ? String(
                data.service_name
              ).trim()
            : existing.service_name;

        const serviceType =
          data.service_type !==
          undefined
            ? String(
                data.service_type
              ).trim()
            : existing.service_type;

        const allowedTypes = [
          "google_review",
          "wifi",
          "menu",
          "digital_card",
          "custom_link"
        ];

        if (
          !allowedTypes.includes(
            serviceType
          )
        ) {
          return json(
            {
              success: false,
              error:
                "Type de service invalide."
            },
            400
          );
        }

        let destinationUrl =
          data.destination_url !==
          undefined
            ? (
                data.destination_url
                  ? String(
                      data.destination_url
                    ).trim()
                  : null
              )
            : existing.destination_url;

        if (destinationUrl) {
          try {
            const parsed =
              new URL(destinationUrl);

            if (
              parsed.protocol !==
                "https:" &&
              parsed.protocol !==
                "http:"
            ) {
              return json(
                {
                  success: false,
                  error:
                    "URL HTTP/HTTPS uniquement."
                },
                400
              );
            }

          } catch {
            return json(
              {
                success: false,
                error:
                  "URL invalide."
              },
              400
            );
          }
        }

        const status =
          data.status !== undefined
            ? String(data.status)
            : existing.status;

        if (
          ![
            "draft",
            "active",
            "inactive"
          ].includes(status)
        ) {
          return json(
            {
              success: false,
              error:
                "Status invalide."
            },
            400
          );
        }

        if (
          status === "active" &&
          !destinationUrl
        ) {
          return json(
            {
              success: false,
              error:
                "Une destination URL est obligatoire pour activer le service."
            },
            400
          );
        }

        let standId =
          existing.stand_id;

        if (
          data.stand_id !==
          undefined
        ) {
          if (
            data.stand_id === null ||
            data.stand_id === ""
          ) {
            standId = null;

          } else {
            standId =
              Number(data.stand_id);

            if (
              !Number.isInteger(
                standId
              )
            ) {
              return json(
                {
                  success: false,
                  error:
                    "stand_id invalide."
                },
                400
              );
            }

            const stand =
              await env.DB
                .prepare(`
                  SELECT id
                  FROM stands
                  WHERE id = ?
                  LIMIT 1
                `)
                .bind(standId)
                .first();

            if (!stand) {
              return json(
                {
                  success: false,
                  error:
                    "Stand introuvable."
                },
                404
              );
            }
          }
        }

        let config =
          existing.config;

        if (
          data.config !==
          undefined
        ) {
          if (
            data.config === null ||
            data.config === ""
          ) {
            config = null;

          } else if (
            typeof data.config ===
            "string"
          ) {
            try {
              JSON.parse(
                data.config
              );

              config =
                data.config;

            } catch {
              return json(
                {
                  success: false,
                  error:
                    "config JSON invalide."
                },
                400
              );
            }

          } else {
            config =
              JSON.stringify(
                data.config
              );
          }
        }

        let activatedAt =
          existing.activated_at;

        if (
          status === "active" &&
          existing.status !==
            "active"
        ) {
          activatedAt =
            new Date()
              .toISOString()
              .replace("T", " ")
              .replace("Z", "");
        }

        if (status !== "active") {
          activatedAt =
            existing.activated_at;
        }

        await env.DB
          .prepare(`
            UPDATE services
            SET
              service_type = ?,
              service_name = ?,
              status = ?,
              destination_url = ?,
              stand_id = ?,
              config = ?,
              activated_at = ?,
              updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
          `)
          .bind(
            serviceType,
            serviceName,
            status,
            destinationUrl,
            standId,
            config,
            activatedAt,
            serviceId
          )
          .run();

        const updated =
          await env.DB
            .prepare(`
              SELECT *
              FROM services
              WHERE id = ?
              LIMIT 1
            `)
            .bind(serviceId)
            .first();

        return json({
          success: true,
          message:
            "Service modifié avec succès.",
          service: updated,
          dynamic_url:
            `${url.origin}/s/${updated.service_code}`
        });

      } catch (error) {
        return json(
          {
            success: false,
            error: error.message
          },
          500
        );
      }
    }


    // =====================================================
    // DELETE SERVICE
    // =====================================================

    if (
      url.pathname.match(
        /^\/api\/services\/\d+$/
      ) &&
      request.method === "DELETE"
    ) {
      if (!(await isAdmin())) {
        return json(
          {
            success: false,
            error: "Non autorisé."
          },
          401
        );
      }

      try {
        const serviceId =
          Number(
            url.pathname
              .split("/")[3]
          );

        const existing =
          await env.DB
            .prepare(`
              SELECT id, service_name
              FROM services
              WHERE id = ?
              LIMIT 1
            `)
            .bind(serviceId)
            .first();

        if (!existing) {
          return json(
            {
              success: false,
              error:
                "Service introuvable."
            },
            404
          );
        }

        await env.DB
          .prepare(`
            DELETE FROM services
            WHERE id = ?
          `)
          .bind(serviceId)
          .run();

        return json({
          success: true,
          message:
            "Service supprimé avec succès."
        });

      } catch (error) {
        return json(
          {
            success: false,
            error: error.message
          },
          500
        );
      }
    }


    // =====================================================
    // SERVICE STATISTICS
    // =====================================================

    if (
      url.pathname.match(
        /^\/api\/services\/\d+\/stats$/
      ) &&
      request.method === "GET"
    ) {
      if (!(await isAdmin())) {
        return json(
          {
            success: false,
            error: "Non autorisé."
          },
          401
        );
      }

      try {
        const serviceId =
          Number(
            url.pathname
              .split("/")[3]
          );

        const service =
          await env.DB
            .prepare(`
              SELECT
                s.*,
                c.name AS client_name
              FROM services s
              LEFT JOIN clients c
                ON s.client_id = c.id
              WHERE s.id = ?
              LIMIT 1
            `)
            .bind(serviceId)
            .first();

        if (!service) {
          return json(
            {
              success: false,
              error:
                "Service introuvable."
            },
            404
          );
        }

        const total =
          await env.DB
            .prepare(`
              SELECT COUNT(*) AS count
              FROM service_scans
              WHERE service_id = ?
            `)
            .bind(serviceId)
            .first();

        const today =
          await env.DB
            .prepare(`
              SELECT COUNT(*) AS count
              FROM service_scans
              WHERE
                service_id = ?
                AND date(scanned_at)
                  = date('now')
            `)
            .bind(serviceId)
            .first();

        const sevenDays =
          await env.DB
            .prepare(`
              SELECT COUNT(*) AS count
              FROM service_scans
              WHERE
                service_id = ?
                AND scanned_at >= datetime(
                  'now',
                  '-7 days'
                )
            `)
            .bind(serviceId)
            .first();

        const thirtyDays =
          await env.DB
            .prepare(`
              SELECT COUNT(*) AS count
              FROM service_scans
              WHERE
                service_id = ?
                AND scanned_at >= datetime(
                  'now',
                  '-30 days'
                )
            `)
            .bind(serviceId)
            .first();

        const lastScan =
          await env.DB
            .prepare(`
              SELECT scanned_at
              FROM service_scans
              WHERE service_id = ?
              ORDER BY id DESC
              LIMIT 1
            `)
            .bind(serviceId)
            .first();

        return json({
          success: true,
          service,
          statistics: {
            total:
              Number(total?.count || 0),

            today:
              Number(today?.count || 0),

            seven_days:
              Number(
                sevenDays?.count || 0
              ),

            thirty_days:
              Number(
                thirtyDays?.count || 0
              ),

            last_scan:
              lastScan?.scanned_at ||
              null
          }
        });

      } catch (error) {
        return json(
          {
            success: false,
            error: error.message
          },
          500
        );
      }
    }


    // =====================================================
    // =====================================================
    // EXISTING STANDS + SCAN STATISTICS
    // =====================================================
    // =====================================================

    if (
      url.pathname === "/api/stands" &&
      request.method === "GET"
    ) {
      if (!(await isAdmin())) {
        return json(
          {
            success: false,
            error: "Non autorisé."
          },
          401
        );
      }

      try {
        const result =
          await env.DB
            .prepare(`
              SELECT
                s.id,
                s.stand_code,
                s.client_id,
                s.destination_url,
                s.status,
                s.created_at,
                s.activated_at,
                c.name AS client_name,

                (
                  SELECT COUNT(*)
                  FROM stand_scans ss
                  WHERE ss.stand_code =
                    s.stand_code
                ) AS scans_count,

                (
                  SELECT COUNT(*)
                  FROM stand_scans ss
                  WHERE
                    ss.stand_code =
                      s.stand_code
                    AND date(ss.scanned_at)
                      = date('now')
                ) AS scans_today,

                (
                  SELECT COUNT(*)
                  FROM stand_scans ss
                  WHERE
                    ss.stand_code =
                      s.stand_code
                    AND ss.scanned_at >=
                      datetime(
                        'now',
                        '-7 days'
                      )
                ) AS scans_7_days,

                (
                  SELECT MAX(ss.scanned_at)
                  FROM stand_scans ss
                  WHERE ss.stand_code =
                    s.stand_code
                ) AS last_scan

              FROM stands s

              LEFT JOIN clients c
                ON s.client_id = c.id

              ORDER BY s.id ASC
            `)
            .all();

        return json({
          success: true,
          stands: result.results
        });

      } catch (error) {
        return json(
          {
            success: false,
            error: error.message
          },
          500
        );
      }
    }


    // =====================================================
    // ACTIVATE STAND
    // =====================================================

    if (
      url.pathname ===
        "/api/stands/activate" &&
      request.method === "POST"
    ) {
      if (!(await isAdmin())) {
        return json(
          {
            success: false,
            error: "Non autorisé."
          },
          401
        );
      }

      try {
        const data =
          await request.json();

        const standCode =
          String(
            data.stand_code || ""
          ).trim();

        const destinationUrl =
          String(
            data.destination_url || ""
          ).trim();

        const clientId =
          data.client_id
            ? Number(data.client_id)
            : null;

        if (!standCode) {
          return json(
            {
              success: false,
              error:
                "stand_code est obligatoire."
            },
            400
          );
        }

        if (!destinationUrl) {
          return json(
            {
              success: false,
              error:
                "destination_url est obligatoire."
            },
            400
          );
        }

        let parsedUrl;

        try {
          parsedUrl =
            new URL(destinationUrl);
        } catch {
          return json(
            {
              success: false,
              error: "URL invalide."
            },
            400
          );
        }

        if (
          parsedUrl.protocol !==
            "https:" &&
          parsedUrl.protocol !==
            "http:"
        ) {
          return json(
            {
              success: false,
              error:
                "URL HTTP/HTTPS uniquement."
            },
            400
          );
        }

        const stand =
          await env.DB
            .prepare(`
              SELECT *
              FROM stands
              WHERE stand_code = ?
              LIMIT 1
            `)
            .bind(standCode)
            .first();

        if (!stand) {
          return json(
            {
              success: false,
              error:
                "Stand introuvable."
            },
            404
          );
        }

        if (
          stand.status ===
          "active"
        ) {
          return json(
            {
              success: false,
              error:
                "Ce Stand est déjà activé."
            },
            409
          );
        }

        if (clientId !== null) {
          const client =
            await env.DB
              .prepare(`
                SELECT id
                FROM clients
                WHERE id = ?
                LIMIT 1
              `)
              .bind(clientId)
              .first();

          if (!client) {
            return json(
              {
                success: false,
                error:
                  "Client introuvable."
              },
              404
            );
          }
        }

        await env.DB
          .prepare(`
            UPDATE stands
            SET
              client_id = ?,
              destination_url = ?,
              status = 'active',
              activated_at =
                CURRENT_TIMESTAMP
            WHERE stand_code = ?
          `)
          .bind(
            clientId,
            destinationUrl,
            standCode
          )
          .run();

        return json({
          success: true,
          message:
            "Stand activé avec succès.",
          stand_code:
            standCode
        });

      } catch (error) {
        return json(
          {
            success: false,
            error: error.message
          },
          500
        );
      }
    }


    // =====================================================
    // RESET STAND
    // =====================================================

    if (
      url.pathname ===
        "/api/stands/reset" &&
      request.method === "POST"
    ) {
      if (!(await isAdmin())) {
        return json(
          {
            success: false,
            error: "Non autorisé."
          },
          401
        );
      }

      try {
        const data =
          await request.json();

        const standCode =
          String(
            data.stand_code || ""
          ).trim();

        if (!standCode) {
          return json(
            {
              success: false,
              error:
                "stand_code est obligatoire."
            },
            400
          );
        }

        const stand =
          await env.DB
            .prepare(`
              SELECT *
              FROM stands
              WHERE stand_code = ?
              LIMIT 1
            `)
            .bind(standCode)
            .first();

        if (!stand) {
          return json(
            {
              success: false,
              error:
                "Stand introuvable."
            },
            404
          );
        }

        await env.DB
          .prepare(`
            UPDATE stands
            SET
              client_id = NULL,
              destination_url = NULL,
              status = 'available',
              activated_at = NULL
            WHERE stand_code = ?
          `)
          .bind(standCode)
          .run();

        return json({
          success: true,
          message:
            "Stand réinitialisé avec succès.",
          stand_code:
            standCode
        });

      } catch (error) {
        return json(
          {
            success: false,
            error: error.message
          },
          500
        );
      }
    }


    // =====================================================
    // =====================================================
    // EXISTING DYNAMIC STAND QR / NFC
    // =====================================================
    // =====================================================

    if (
      url.pathname.startsWith("/r/")
    ) {
      const standCode =
        url.pathname
          .replace("/r/", "")
          .replace(/\/$/, "");

      if (!standCode) {
        return new Response(
          "Stand introuvable",
          { status: 404 }
        );
      }

      try {
        const stand =
          await env.DB
            .prepare(`
              SELECT
                stand_code,
                destination_url,
                status
              FROM stands
              WHERE stand_code = ?
              LIMIT 1
            `)
            .bind(standCode)
            .first();

        if (!stand) {
          return new Response(
            "Stand introuvable",
            { status: 404 }
          );
        }

        if (
          stand.status !==
            "active" ||
          !stand.destination_url
        ) {
          return new Response(
            `
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport"
content="width=device-width,initial-scale=1.0">
<title>TAPNIVO</title>
<style>
*{box-sizing:border-box}
body{
margin:0;
min-height:100vh;
display:flex;
align-items:center;
justify-content:center;
font-family:Arial,Helvetica,sans-serif;
background:#f5f7fb;
color:#111827;
text-align:center;
}
.box{
background:white;
padding:35px 25px;
border-radius:20px;
box-shadow:0 15px 40px rgba(0,0,0,.08);
max-width:400px;
margin:20px;
}
.logo{
font-size:24px;
font-weight:800;
margin-bottom:20px;
}
.logo span{color:#4f46e5}
p{
color:#6b7280;
line-height:1.6;
}
</style>
</head>
<body>
<div class="box">
<div class="logo">
TAP<span>NIVO</span>
</div>
<h2>Stand non activé</h2>
<p>
Ce QR code est prêt à être activé.
</p>
</div>
</body>
</html>
`,
            {
              status: 200,
              headers: {
                "Content-Type":
                  "text/html; charset=UTF-8"
              }
            }
          );
        }

        await env.DB
          .prepare(`
            INSERT INTO stand_scans (
              stand_code
            )
            VALUES (?)
          `)
          .bind(standCode)
          .run();

        return Response.redirect(
          stand.destination_url,
          302
        );

      } catch (error) {
        return new Response(
          "Erreur serveur : " +
          error.message,
          { status: 500 }
        );
      }
    }


    // =====================================================
    // =====================================================
    // DYNAMIC SERVICE QR
    // =====================================================
    // =====================================================

    if (
      url.pathname.startsWith("/s/")
    ) {
      const serviceCode =
        url.pathname
          .replace("/s/", "")
          .replace(/\/$/, "");

      if (!serviceCode) {
        return new Response(
          "Service introuvable",
          { status: 404 }
        );
      }

      try {
        const service =
          await env.DB
            .prepare(`
              SELECT
                s.*,
                c.name AS client_name
              FROM services s
              LEFT JOIN clients c
                ON s.client_id = c.id
              WHERE s.service_code = ?
              LIMIT 1
            `)
            .bind(serviceCode)
            .first();

        if (!service) {
          return new Response(
            "Service introuvable",
            { status: 404 }
          );
        }

        if (
          service.status !==
            "active"
        ) {
          return new Response(
            `
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport"
content="width=device-width,
initial-scale=1.0">
<title>TAPNIVO</title>

<style>
*{box-sizing:border-box}

body{
margin:0;
min-height:100vh;
display:flex;
align-items:center;
justify-content:center;
font-family:Arial,Helvetica,sans-serif;
background:#f5f7fb;
color:#111827;
text-align:center;
}

.box{
background:white;
padding:35px 25px;
border-radius:20px;
box-shadow:0 15px 40px rgba(0,0,0,.08);
max-width:420px;
margin:20px;
}

.logo{
font-size:24px;
font-weight:800;
margin-bottom:20px;
}

.logo span{
color:#4f46e5;
}

p{
color:#6b7280;
line-height:1.6;
}
</style>

</head>

<body>

<div class="box">

<div class="logo">
TAP<span>NIVO</span>
</div>

<h2>
Service non disponible
</h2>

<p>
Ce service n'est pas encore activé.
</p>

</div>

</body>
</html>
`,
            {
              status: 200,
              headers: {
                "Content-Type":
                  "text/html; charset=UTF-8"
              }
            }
          );
        }

        // =================================================
        // ENREGISTRER LE SCAN
        // =================================================

        await env.DB
          .prepare(`
            INSERT INTO service_scans (
              service_id
            )
            VALUES (?)
          `)
          .bind(service.id)
          .run();

        // =================================================
        // DESTINATION
        // =================================================

        if (
          service.destination_url
        ) {
          return Response.redirect(
            service.destination_url,
            302
          );
        }

        return new Response(
          `
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport"
content="width=device-width,
initial-scale=1.0">
<title>
${escapeHTML(
  service.service_name
)}
</title>
</head>

<body>

<div style="
font-family:Arial;
text-align:center;
padding:50px 20px;
">

<h2>
${escapeHTML(
  service.service_name
)}
</h2>

<p>
Ce service est actif mais
n'a pas encore de destination.
</p>

</div>

</body>
</html>
`,
          {
            status: 200,
            headers: {
              "Content-Type":
                "text/html; charset=UTF-8"
            }
          }
        );

      } catch (error) {
        return new Response(
          "Erreur serveur : " +
          error.message,
          { status: 500 }
        );
      }
    }


    // =====================================================
    // =====================================================
    // CLIENT PROFILE
    // =====================================================
    // =====================================================

    if (
      url.pathname.startsWith(
        "/client/"
      )
    ) {
      const slug =
        url.pathname
          .replace(
            "/client/",
            ""
          )
          .replace(/\/$/, "");

      if (!slug) {
        return new Response(
          "Profil introuvable",
          { status: 404 }
        );
      }

      try {
        const result =
          await env.DB
            .prepare(`
              SELECT *
              FROM clients
              WHERE slug = ?
              LIMIT 1
            `)
            .bind(slug)
            .first();

        if (!result) {
          return new Response(
            "Client introuvable",
            { status: 404 }
          );
        }

        const html = `
<!DOCTYPE html>
<html lang="fr">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,
initial-scale=1.0">

<title>
${escapeHTML(
  result.name
)} | TAPNIVO
</title>

<style>

*{
box-sizing:border-box
}

body{
margin:0;
font-family:Arial,Helvetica,sans-serif;
background:
linear-gradient(
135deg,
#f5f7fb,
#eef2ff
);
color:#111827;
}

.container{
max-width:600px;
margin:auto;
padding:40px 20px;
}

.profile{
background:white;
border-radius:25px;
padding:35px 25px;
text-align:center;
box-shadow:
0 15px 40px
rgba(0,0,0,.08);
}

.logo{
font-size:20px;
font-weight:800;
margin-bottom:30px;
}

.logo span{
color:#4f46e5;
}

.avatar{
width:100px;
height:100px;
border-radius:50%;
margin:auto auto 20px;
background:#eef2ff;
display:flex;
align-items:center;
justify-content:center;
font-size:40px;
}

h1{
margin:0;
font-size:28px;
}

.profession{
color:#4f46e5;
font-weight:bold;
margin-top:8px;
}

.bio{
color:#6b7280;
line-height:1.6;
margin:20px 0;
}

.buttons{
display:grid;
gap:10px;
margin-top:25px;
}

.button{
display:block;
padding:14px;
border-radius:12px;
text-decoration:none;
font-weight:bold;
background:#4f46e5;
color:white;
}

.button.secondary{
background:#f3f4f6;
color:#374151;
}

.info{
margin-top:25px;
text-align:left;
}

.info div{
padding:12px 0;
border-bottom:1px solid #eee;
}

.label{
font-size:12px;
color:#9ca3af;
}

.value{
margin-top:4px;
font-weight:600;
}

.footer{
margin-top:25px;
color:#9ca3af;
font-size:12px;
}

</style>

</head>

<body>

<div class="container">

<div class="profile">

<div class="logo">
TAP<span>NIVO</span>
</div>

<div class="avatar">
👤
</div>

<h1>
${escapeHTML(
  result.name
)}
</h1>

${
  result.profession
    ? `
<div class="profession">
${escapeHTML(
  result.profession
)}
</div>
`
    : ""
}

${
  result.bio
    ? `
<div class="bio">
${escapeHTML(
  result.bio
)}
</div>
`
    : ""
}

<div class="buttons">

${
  result.phone
    ? `
<a
class="button"
href="tel:${escapeHTML(
  result.phone
)}"
>
📞 Appeler
</a>
`
    : ""
}

${
  result.whatsapp
    ? `
<a
class="button"
href="https://wa.me/${escapeHTML(
  result.whatsapp
    .replace(
      /[^0-9]/g,
      ""
    )
)}"
target="_blank"
>
💬 WhatsApp
</a>
`
    : ""
}

${
  result.instagram
    ? `
<a
class="button secondary"
href="${escapeHTML(
  result.instagram
)}"
target="_blank"
>
Instagram
</a>
`
    : ""
}

${
  result.maps
    ? `
<a
class="button secondary"
href="${escapeHTML(
  result.maps
)}"
target="_blank"
>
📍 Google Maps
</a>
`
    : ""
}

</div>

<div class="info">

${
  result.email
    ? `
<div>
<div class="label">
Email
</div>

<div class="value">
${escapeHTML(
  result.email
)}
</div>

</div>
`
    : ""
}

${
  result.address
    ? `
<div>

<div class="label">
Adresse
</div>

<div class="value">
${escapeHTML(
  result.address
)}
</div>

</div>
`
    : ""
}

</div>

<div class="footer">
Profil digital créé avec TAPNIVO
</div>

</div>

</div>

</body>

</html>
`;

        return new Response(
          html,
          {
            headers: {
              "Content-Type":
                "text/html; charset=UTF-8"
            }
          }
        );

      } catch (error) {
        return new Response(
          "Erreur serveur : " +
          error.message,
          { status: 500 }
        );
      }
    }


    // =====================================================
    // STATIC FILES
    // =====================================================

    return env.ASSETS.fetch(request);
  }
};
