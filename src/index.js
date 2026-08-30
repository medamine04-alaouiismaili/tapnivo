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

    const html = (content, status = 200) => {
      return new Response(content, {
        status,
        headers: {
          "Content-Type": "text/html; charset=UTF-8"
        }
      });
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

    const getCookie = (request, name) => {
      const cookieHeader = request.headers.get("Cookie");

      if (!cookieHeader) {
        return null;
      }

      const cookies = cookieHeader.split(";");

      for (const cookie of cookies) {
        const parts = cookie.trim().split("=");

        if (parts[0] === name) {
          return parts.slice(1).join("=");
        }
      }

      return null;
    };

    // =====================================================
    // ADMIN AUTH
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

        const now = Date.now();

        if (now - time > 8 * 60 * 60 * 1000) {
          return false;
        }

        if (time > now + 60000) {
          return false;
        }

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

    const isAdmin = async () => {
      const token =
        getCookie(request, "tapnivo_admin");

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
        const data = await request.json();

        const password =
          String(data.password || "");

        if (!env.ADMIN_KEY) {
          return json(
            {
              success: false,
              error: "ADMIN_KEY non configurée."
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
              error: "Mot de passe incorrect."
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

    if (url.pathname === "/api/test-db") {
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
    // CLIENTS
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

    if (
      url.pathname === "/api/clients" &&
      request.method === "POST"
    ) {
      try {
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

        let baseSlug =
          String(data.name)
            .toLowerCase()
            .normalize("NFD")
            .replace(/[\u0300-\u036f]/g, "")
            .replace(/[^a-z0-9]+/g, "-")
            .replace(/^-|-$/g, "");

        if (!baseSlug) {
          baseSlug = "client";
        }

        const slug =
          data.slug ||
          baseSlug +
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
    // STANDS
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
                  WHERE ss.stand_code = s.stand_code
                ) AS scans_count,

                (
                  SELECT MAX(ss.scanned_at)
                  FROM stand_scans ss
                  WHERE ss.stand_code = s.stand_code
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
      url.pathname === "/api/stands/activate" &&
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

        try {
          const parsedUrl =
            new URL(destinationUrl);

          if (
            parsedUrl.protocol !== "https:" &&
            parsedUrl.protocol !== "http:"
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
              error: "URL invalide."
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
              error: "Stand introuvable."
            },
            404
          );
        }

        if (stand.status === "active") {
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
                error: "Client introuvable."
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
              activated_at = CURRENT_TIMESTAMP
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
          stand_code: standCode
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
      url.pathname === "/api/stands/reset" &&
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
              error: "Stand introuvable."
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
          stand_code: standCode
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
    // SERVICES - HELPERS
    // =====================================================

    const generateServiceCode = () => {
      const chars =
        "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

      let code = "";

      for (let i = 0; i < 8; i++) {
        code +=
          chars[
            Math.floor(
              Math.random() *
              chars.length
            )
          ];
      }

      return code;
    };

    const parseConfig = (value) => {
      if (!value) {
        return null;
      }

      if (typeof value === "object") {
        return value;
      }

      try {
        return JSON.parse(value);
      } catch {
        return value;
      }
    };

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
                s.service_code,
                s.destination_url,
                s.stand_id,
                s.status,
                s.config,
                s.created_at,
                s.activated_at,
                s.updated_at,

                c.name AS client_name,

                st.stand_code AS stand_code,

                (
                  SELECT COUNT(*)
                  FROM service_scans ss
                  WHERE ss.service_id = s.id
                ) AS scans_count,

                (
                  SELECT COUNT(*)
                  FROM service_scans ss
                  WHERE ss.service_id = s.id
                  AND date(ss.scanned_at) = date('now')
                ) AS scans_today,

                (
                  SELECT COUNT(*)
                  FROM service_scans ss
                  WHERE ss.service_id = s.id
                  AND ss.scanned_at >= datetime('now','-7 days')
                ) AS scans_7_days,

                (
                  SELECT COUNT(*)
                  FROM service_scans ss
                  WHERE ss.service_id = s.id
                  AND ss.scanned_at >= datetime('now','-30 days')
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

        const services =
          result.results.map(service => ({
            ...service,
            config:
              parseConfig(service.config)
          }));

        return json({
          success: true,
          services
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

        const serviceType =
          String(
            data.service_type || ""
          ).trim();

        const serviceName =
          String(
            data.service_name || ""
          ).trim();

        const destinationUrl =
          String(
            data.destination_url || ""
          ).trim();

        const status =
          String(
            data.status || "draft"
          ).trim();

        const standId =
          data.stand_id
            ? Number(data.stand_id)
            : null;

        if (!clientId) {
          return json(
            {
              success: false,
              error:
                "client_id est obligatoire."
            },
            400
          );
        }

        if (!serviceType) {
          return json(
            {
              success: false,
              error:
                "service_type est obligatoire."
            },
            400
          );
        }

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

        if (!serviceName) {
          return json(
            {
              success: false,
              error:
                "service_name est obligatoire."
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
              error: "Client introuvable."
            },
            404
          );
        }

        if (standId !== null) {
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
                error: "Stand introuvable."
              },
              404
            );
          }
        }

        if (destinationUrl) {
          try {
            const parsed =
              new URL(destinationUrl);

            if (
              parsed.protocol !== "http:" &&
              parsed.protocol !== "https:"
            ) {
              return json(
                {
                  success: false,
                  error:
                    "Destination URL invalide."
                },
                400
              );
            }

          } catch {
            return json(
              {
                success: false,
                error:
                  "Destination URL invalide."
              },
              400
            );
          }
        }

        const config =
          data.config !== undefined &&
          data.config !== null
            ? typeof data.config === "string"
              ? data.config
              : JSON.stringify(data.config)
            : null;

        let serviceCode = "";

        for (let i = 0; i < 10; i++) {
          const candidate =
            generateServiceCode();

          const exists =
            await env.DB
              .prepare(`
                SELECT id
                FROM services
                WHERE service_code = ?
                LIMIT 1
              `)
              .bind(candidate)
              .first();

          if (!exists) {
            serviceCode =
              candidate;
            break;
          }
        }

        if (!serviceCode) {
          return json(
            {
              success: false,
              error:
                "Impossible de générer un code unique."
            },
            500
          );
        }

        const activatedAt =
          status === "active"
            ? "CURRENT_TIMESTAMP"
            : "NULL";

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
              ${activatedAt},
              CURRENT_TIMESTAMP
            )
          `)
          .bind(
            clientId,
            serviceType,
            serviceName,
            status,
            serviceCode,
            destinationUrl || null,
            standId,
            config
          )
          .run();

        return json({
          success: true,
          message:
            "Service créé avec succès.",
          service_code:
            serviceCode
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
    // SERVICE ID PARSE
    // =====================================================

    const serviceIdMatch =
      url.pathname.match(
        /^\/api\/services\/(\d+)(?:\/stats)?$/
      );

    const serviceId =
      serviceIdMatch
        ? Number(serviceIdMatch[1])
        : null;

    // =====================================================
    // SERVICE STATS
    // =====================================================

    if (
      serviceId !== null &&
      url.pathname ===
        `/api/services/${serviceId}/stats` &&
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
        const service =
          await env.DB
            .prepare(`
              SELECT
                s.id,
                s.service_name,
                s.service_type,
                s.service_code,
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

        const statistics =
          await env.DB
            .prepare(`
              SELECT

                COUNT(*) AS total,

                SUM(
                  CASE
                    WHEN date(scanned_at) = date('now')
                    THEN 1
                    ELSE 0
                  END
                ) AS today,

                SUM(
                  CASE
                    WHEN scanned_at >= datetime('now','-7 days')
                    THEN 1
                    ELSE 0
                  END
                ) AS seven_days,

                SUM(
                  CASE
                    WHEN scanned_at >= datetime('now','-30 days')
                    THEN 1
                    ELSE 0
                  END
                ) AS thirty_days,

                MAX(scanned_at) AS last_scan

              FROM service_scans

              WHERE service_id = ?
            `)
            .bind(serviceId)
            .first();

        return json({
          success: true,
          service,
          statistics: {
            total:
              Number(
                statistics?.total || 0
              ),
            today:
              Number(
                statistics?.today || 0
              ),
            seven_days:
              Number(
                statistics?.seven_days || 0
              ),
            thirty_days:
              Number(
                statistics?.thirty_days || 0
              ),
            last_scan:
              statistics?.last_scan ||
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
    // UPDATE SERVICE
    // =====================================================

    if (
      serviceId !== null &&
      url.pathname ===
        `/api/services/${serviceId}` &&
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

        const updates = [];
        const values = [];

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "client_id"
          )
        ) {
          const clientId =
            Number(data.client_id);

          if (!clientId) {
            return json(
              {
                success: false,
                error:
                  "client_id invalide."
              },
              400
            );
          }

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

          updates.push(
            "client_id = ?"
          );

          values.push(clientId);
        }

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "service_type"
          )
        ) {
          const type =
            String(
              data.service_type || ""
            ).trim();

          const allowedTypes = [
            "google_review",
            "wifi",
            "menu",
            "digital_card",
            "custom_link"
          ];

          if (
            !allowedTypes.includes(type)
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

          updates.push(
            "service_type = ?"
          );

          values.push(type);
        }

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "service_name"
          )
        ) {
          const name =
            String(
              data.service_name || ""
            ).trim();

          if (!name) {
            return json(
              {
                success: false,
                error:
                  "Nom du service obligatoire."
              },
              400
            );
          }

          updates.push(
            "service_name = ?"
          );

          values.push(name);
        }

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "destination_url"
          )
        ) {
          const destination =
            String(
              data.destination_url || ""
            ).trim();

          if (destination) {
            try {
              const parsed =
                new URL(destination);

              if (
                parsed.protocol !== "http:" &&
                parsed.protocol !== "https:"
              ) {
                return json(
                  {
                    success: false,
                    error:
                      "URL invalide."
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

          updates.push(
            "destination_url = ?"
          );

          values.push(
            destination || null
          );
        }

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "stand_id"
          )
        ) {
          const standId =
            data.stand_id
              ? Number(data.stand_id)
              : null;

          if (standId !== null) {
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

          updates.push(
            "stand_id = ?"
          );

          values.push(
            standId
          );
        }

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "config"
          )
        ) {
          const config =
            data.config === null
              ? null
              : typeof data.config ===
                "string"
                ? data.config
                : JSON.stringify(
                    data.config
                  );

          updates.push(
            "config = ?"
          );

          values.push(config);
        }

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "status"
          )
        ) {
          const status =
            String(
              data.status || ""
            ).trim();

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
                  "Statut invalide."
              },
              400
            );
          }

          updates.push(
            "status = ?"
          );

          values.push(status);

          if (status === "active") {
            updates.push(
              "activated_at = COALESCE(activated_at, CURRENT_TIMESTAMP)"
            );
          }

          if (
            status === "draft" ||
            status === "inactive"
          ) {
            updates.push(
              "activated_at = NULL"
            );
          }
        }

        if (!updates.length) {
          return json({
            success: true,
            message:
              "Aucune modification."
          });
        }

        updates.push(
          "updated_at = CURRENT_TIMESTAMP"
        );

        values.push(serviceId);

        await env.DB
          .prepare(`
            UPDATE services
            SET ${updates.join(", ")}
            WHERE id = ?
          `)
          .bind(...values)
          .run();

        return json({
          success: true,
          message:
            "Service modifié avec succès."
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
      serviceId !== null &&
      url.pathname ===
        `/api/services/${serviceId}` &&
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
        const service =
          await env.DB
            .prepare(`
              SELECT id
              FROM services
              WHERE id = ?
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
    // DYNAMIC SERVICE QR
    // /s/SERVICECODE
    // =====================================================

    if (
      url.pathname.startsWith("/s/")
    ) {
      const serviceCode =
        url.pathname
          .replace("/s/", "")
          .replace(/\/$/, "")
          .trim();

      if (!serviceCode) {
        return html(
          "<h1>Service introuvable</h1>",
          404
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
          return html(
            `
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TAPNIVO</title>
<style>
body{
  margin:0;
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  font-family:Arial,sans-serif;
  background:#f5f7fb;
}
.box{
  background:white;
  padding:35px;
  border-radius:20px;
  text-align:center;
  box-shadow:0 15px 40px rgba(0,0,0,.08);
}
.logo{
  font-size:25px;
  font-weight:800;
}
.logo span{
  color:#4f46e5;
}
</style>
</head>
<body>
<div class="box">
<div class="logo">
TAP<span>NIVO</span>
</div>
<h2>Service introuvable</h2>
<p>Ce QR code n'existe pas.</p>
</div>
</body>
</html>
`,
            404
          );
        }

        if (
          service.status !== "active"
        ) {
          return html(
            `
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TAPNIVO</title>
<style>
body{
  margin:0;
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  font-family:Arial,sans-serif;
  background:#f5f7fb;
}
.box{
  background:white;
  padding:35px;
  border-radius:20px;
  text-align:center;
  max-width:400px;
  box-shadow:0 15px 40px rgba(0,0,0,.08);
}
.logo{
  font-size:25px;
  font-weight:800;
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
<h2>Service indisponible</h2>
<p>
Ce service n'est pas actuellement disponible.
</p>
</div>
</body>
</html>
`,
            200
          );
        }

        // =================================================
        // SCAN
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
        // CONFIG
        // =================================================

        const config =
          parseConfig(
            service.config
          );

        // =================================================
        // WIFI
        // =================================================

        if (
          service.service_type ===
          "wifi"
        ) {
          const ssid =
            config &&
            typeof config === "object"
              ? config.wifi_name ||
                config.ssid ||
                ""
              : "";

          const password =
            config &&
            typeof config === "object"
              ? config.password ||
                ""
              : "";

          const security =
            config &&
            typeof config === "object"
              ? config.security ||
                "WPA"
              : "WPA";

          const htmlWifi = `
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHTML(
            service.service_name
          )}</title>

<style>
*{
box-sizing:border-box;
}

body{
margin:0;
min-height:100vh;
display:flex;
align-items:center;
justify-content:center;
font-family:Arial,Helvetica,sans-serif;
background:linear-gradient(
135deg,
#f5f7fb,
#eef2ff
);
color:#111827;
padding:20px;
}

.box{
width:100%;
max-width:430px;
background:white;
border-radius:25px;
padding:30px;
text-align:center;
box-shadow:0 15px 45px rgba(0,0,0,.09);
}

.logo{
font-size:21px;
font-weight:800;
margin-bottom:25px;
}

.logo span{
color:#4f46e5;
}

.icon{
font-size:50px;
margin-bottom:10px;
}

h1{
font-size:25px;
margin:0;
}

.client{
color:#6b7280;
margin-top:8px;
}

.wifi{
margin-top:25px;
background:#f9fafb;
border-radius:15px;
padding:20px;
text-align:left;
}

.row{
padding:12px 0;
border-bottom:1px solid #e5e7eb;
}

.row:last-child{
border-bottom:0;
}

.label{
font-size:11px;
color:#9ca3af;
}

.value{
font-weight:800;
margin-top:5px;
word-break:break-word;
}

.password{
background:#eef2ff;
color:#3730a3;
padding:12px;
border-radius:10px;
margin-top:7px;
font-size:18px;
letter-spacing:1px;
}

.footer{
margin-top:25px;
font-size:11px;
color:#9ca3af;
}
</style>
</head>

<body>

<div class="box">

<div class="logo">
TAP<span>NIVO</span>
</div>

<div class="icon">
📶
</div>

<h1>
${escapeHTML(
  service.service_name
)}
</h1>

<div class="client">
${escapeHTML(
  service.client_name || ""
)}
</div>

<div class="wifi">

<div class="row">
<div class="label">
NOM DU WI-FI
</div>
<div class="value">
${escapeHTML(
  ssid || "—"
)}
</div>
</div>

<div class="row">
<div class="label">
MOT DE PASSE
</div>
<div class="password">
${escapeHTML(
  password || "—"
)}
</div>
</div>

<div class="row">
<div class="label">
SÉCURITÉ
</div>
<div class="value">
${escapeHTML(
  security
)}
</div>
</div>

</div>

<div class="footer">
Service Wi-Fi créé avec TAPNIVO
</div>

</div>

</body>
</html>
`;

          return html(
            htmlWifi
          );
        }

        // =================================================
        // MENU
        // =================================================

        if (
          service.service_type ===
          "menu"
        ) {
          if (
            service.destination_url
          ) {
            return Response.redirect(
              service.destination_url,
              302
            );
          }

          return html(
            `
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Menu</title>
</head>
<body style="
font-family:Arial;
text-align:center;
padding:50px;
">
<h2>🍽️ Menu</h2>
<p>
Le menu sera disponible prochainement.
</p>
</body>
</html>
`
          );
        }

        // =================================================
        // GOOGLE REVIEW
        // =================================================

        if (
          service.service_type ===
          "google_review"
        ) {
          if (
            service.destination_url
          ) {
            return Response.redirect(
              service.destination_url,
              302
            );
          }

          return html(
            `
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Avis Google</title>
</head>
<body style="
font-family:Arial;
text-align:center;
padding:50px;
">
<h2>⭐ Google Reviews</h2>
<p>
Lien Google Reviews non configuré.
</p>
</body>
</html>
`
          );
        }

        // =================================================
        // DIGITAL CARD
        // =================================================

        if (
          service.service_type ===
          "digital_card"
        ) {
          const client =
            await env.DB
              .prepare(`
                SELECT *
                FROM clients
                WHERE id = ?
                LIMIT 1
              `)
              .bind(service.client_id)
              .first();

          if (!client) {
            return html(
              "<h1>Client introuvable</h1>",
              404
            );
          }

          const buttons = [];

          if (client.phone) {
            buttons.push(`
<a href="tel:${escapeHTML(
              client.phone
            )}">
📞 Appeler
</a>
`);
          }

          if (client.whatsapp) {
            buttons.push(`
<a href="https://wa.me/${escapeHTML(
              client.whatsapp.replace(
                /[^0-9]/g,
                ""
              )
            )}" target="_blank">
💬 WhatsApp
</a>
`);
          }

          if (client.instagram) {
            buttons.push(`
<a href="${escapeHTML(
              client.instagram
            )}" target="_blank">
Instagram
</a>
`);
          }

          if (client.maps) {
            buttons.push(`
<a href="${escapeHTML(
              client.maps
            )}" target="_blank">
📍 Google Maps
</a>
`);
          }

          return html(
            `
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHTML(
              client.name
            )}</title>

<style>
body{
margin:0;
font-family:Arial;
background:#f5f7fb;
padding:30px 20px;
}

.card{
max-width:500px;
margin:auto;
background:white;
padding:30px;
border-radius:25px;
text-align:center;
box-shadow:0 15px 40px rgba(0,0,0,.08);
}

.logo{
font-weight:800;
font-size:20px;
margin-bottom:25px;
}

.logo span{
color:#4f46e5;
}

h1{
margin-bottom:5px;
}

.profession{
color:#4f46e5;
font-weight:bold;
}

.bio{
color:#6b7280;
line-height:1.6;
margin:20px 0;
}

a{
display:block;
background:#4f46e5;
color:white;
text-decoration:none;
padding:14px;
border-radius:12px;
margin-top:10px;
font-weight:bold;
}

.footer{
margin-top:25px;
color:#9ca3af;
font-size:11px;
}
</style>
</head>

<body>

<div class="card">

<div class="logo">
TAP<span>NIVO</span>
</div>

<h1>
${escapeHTML(
  client.name
)}
</h1>

<div class="profession">
${escapeHTML(
  client.profession || ""
)}
</div>

<div class="bio">
${escapeHTML(
  client.bio || ""
)}
</div>

${buttons.join("")}

<div class="footer">
Profil digital créé avec TAPNIVO
</div>

</div>

</body>
</html>
`
          );
        }

        // =================================================
        // CUSTOM LINK
        // =================================================

        if (
          service.service_type ===
          "custom_link"
        ) {
          if (
            service.destination_url
          ) {
            return Response.redirect(
              service.destination_url,
              302
            );
          }

          return html(
            `
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TAPNIVO</title>
</head>
<body style="
font-family:Arial;
text-align:center;
padding:50px;
">
<h2>🔗 Lien</h2>
<p>
Aucune destination configurée.
</p>
</body>
</html>
`
          );
        }

        return html(
          `
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TAPNIVO</title>
</head>
<body style="
font-family:Arial;
text-align:center;
padding:50px;
">
<h2>Service TAPNIVO</h2>
<p>
Service configuré mais aucune action disponible.
</p>
</body>
</html>
`
        );

      } catch (error) {
        return html(
          `
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>TAPNIVO</title>
</head>
<body style="
font-family:Arial;
text-align:center;
padding:50px;
">
<h2>Erreur serveur</h2>
<p>${escapeHTML(
            error.message
          )}</p>
</body>
</html>
`,
          500
        );
      }
    }

    // =====================================================
    // EXISTING STAND DYNAMIC QR
    // /r/STANDCODE
    // =====================================================

    if (
      url.pathname.startsWith("/r/")
    ) {
      const standCode =
        url.pathname
          .replace("/r/", "")
          .replace(/\/$/, "")
          .trim();

      if (!standCode) {
        return html(
          "Stand introuvable",
          404
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
          return html(
            "Stand introuvable",
            404
          );
        }

        if (
          stand.status !== "active" ||
          !stand.destination_url
        ) {
          return html(
            `
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TAPNIVO</title>
<style>
body{
margin:0;
min-height:100vh;
display:flex;
align-items:center;
justify-content:center;
font-family:Arial;
background:#f5f7fb;
text-align:center;
}
.box{
background:white;
padding:35px;
border-radius:20px;
box-shadow:0 15px 40px rgba(0,0,0,.08);
}
.logo{
font-size:24px;
font-weight:800;
}
.logo span{
color:#4f46e5;
}
p{
color:#6b7280;
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
`
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
        return html(
          "Erreur serveur : " +
          escapeHTML(error.message),
          500
        );
      }
    }

    // =====================================================
    // CLIENT PROFILE
    // =====================================================

    if (
      url.pathname.startsWith("/client/")
    ) {
      const slug =
        url.pathname
          .replace("/client/", "")
          .replace(/\/$/, "")
          .trim();

      if (!slug) {
        return html(
          "Profil introuvable",
          404
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
          return html(
            "Client introuvable",
            404
          );
        }

        return html(
          `
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">

<title>
${escapeHTML(
            result.name
          )} | TAPNIVO
</title>

<style>

*{
box-sizing:border-box;
}

body{
margin:0;
font-family:Arial,Helvetica,sans-serif;
background:linear-gradient(
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
box-shadow:0 15px 40px rgba(0,0,0,.08);
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
      result.whatsapp.replace(
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
`
        );

      } catch (error) {
        return html(
          "Erreur serveur : " +
          escapeHTML(error.message),
          500
        );
      }
    }

    // =====================================================
    // STATIC FILES
    // =====================================================

    return env.ASSETS.fetch(request);
  }
};
