export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // =====================================================
    // HELPERS
    // =====================================================

    const json = (data, status = 200, extraHeaders = {}) => {
      return new Response(JSON.stringify(data, null, 2), {
        status,
        headers: {
          "Content-Type": "application/json; charset=UTF-8",
          "Cache-Control": "no-store",
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

    const getCookie = (request, name) => {
      const cookieHeader = request.headers.get("Cookie");

      if (!cookieHeader) {
        return null;
      }

      for (const cookie of cookieHeader.split(";")) {
        const parts = cookie.trim().split("=");

        if (parts[0] === name) {
          return parts.slice(1).join("=");
        }
      }

      return null;
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
      const padding =
        (4 - (input.length % 4)) % 4;

      const base64 =
        input
          .replace(/-/g, "+")
          .replace(/_/g, "/") +
        "=".repeat(padding);

      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);

      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }

      return bytes;
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

    const isValidHttpUrl = (value) => {
      if (!value) {
        return false;
      }

      try {
        const parsed = new URL(value);

        return (
          parsed.protocol === "http:" ||
          parsed.protocol === "https:"
        );
      } catch {
        return false;
      }
    };

    // =====================================================
    // ADMIN AUTH
    // =====================================================

    const createAdminToken = async () => {
      if (!env.ADMIN_KEY) {
        throw new Error(
          "ADMIN_KEY non configurée."
        );
      }

      const timestamp =
        Date.now().toString();

      const encoder =
        new TextEncoder();

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

      const signature =
        new Uint8Array(
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
      if (
        !token ||
        !env.ADMIN_KEY
      ) {
        return false;
      }

      const parts =
        token.split(".");

      if (parts.length !== 2) {
        return false;
      }

      try {
        const timestampBytes =
          fromBase64url(parts[0]);

        const timestamp =
          new TextDecoder().decode(
            timestampBytes
          );

        const time =
          Number(timestamp);

        if (!Number.isFinite(time)) {
          return false;
        }

        const now =
          Date.now();

        // 8 hours
        if (
          now - time >
          8 * 60 * 60 * 1000
        ) {
          return false;
        }

        if (
          time >
          now + 60000
        ) {
          return false;
        }

        const encoder =
          new TextEncoder();

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

    const isAdmin = async () => {
      const token =
        getCookie(
          request,
          "tapnivo_admin"
        );

      return await verifyAdminToken(
        token
      );
    };

    // =====================================================
    // ADMIN LOGIN
    // =====================================================

    if (
      url.pathname ===
        "/api/admin/login" &&
      request.method === "POST"
    ) {
      try {
        const data =
          await request.json();

        const password =
          String(
            data.password || ""
          );

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
            error:
              error.message
          },
          500
        );
      }
    }

    // =====================================================
    // ADMIN CHECK
    // =====================================================

    if (
      url.pathname ===
        "/api/admin/me" &&
      request.method === "GET"
    ) {
      return json({
        success: true,
        authenticated:
          await isAdmin()
      });
    }

    // =====================================================
    // ADMIN LOGOUT
    // =====================================================

    if (
      url.pathname ===
        "/api/admin/logout" &&
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
            .prepare(`
              SELECT
                name
              FROM sqlite_master
              WHERE type='table'
              ORDER BY name
            `)
            .all();

        return json({
          success: true,
          database:
            "tapnivo-db",
          tables:
            result.results
        });

      } catch (error) {
        return json(
          {
            success: false,
            error:
              error.message
          },
          500
        );
      }
    }

    // =====================================================
    // CLIENTS - GET
    // =====================================================

    if (
      url.pathname ===
        "/api/clients" &&
      request.method === "GET"
    ) {
      if (!(await isAdmin())) {
        return json(
          {
            success: false,
            error:
              "Non autorisé."
          },
          401
        );
      }

      try {
        const result =
          await env.DB
            .prepare(`
              SELECT *
              FROM clients
              ORDER BY id DESC
            `)
            .all();

        return json({
          success: true,
          clients:
            result.results
        });

      } catch (error) {
        return json(
          {
            success: false,
            error:
              error.message
          },
          500
        );
      }
    }

    // =====================================================
    // CLIENTS - POST
    // =====================================================

    if (
      url.pathname ===
        "/api/clients" &&
      request.method === "POST"
    ) {
      if (!(await isAdmin())) {
        return json(
          {
            success: false,
            error:
              "Non autorisé."
          },
          401
        );
      }

      try {
        const data =
          await request.json();

        const name =
          String(
            data.name || ""
          ).trim();

        if (!name) {
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
          name
            .toLowerCase()
            .normalize("NFD")
            .replace(
              /[\u0300-\u036f]/g,
              ""
            )
            .replace(
              /[^a-z0-9]+/g,
              "-"
            )
            .replace(
              /^-|-$/g,
              ""
            );

        if (!baseSlug) {
          baseSlug =
            "client";
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
            name,
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
            error:
              error.message
          },
          500
        );
      }
    }

    // =====================================================
    // STAND HELPERS
    // =====================================================

    const STAND_CHARS =
      "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    const randomChars = (length = 8) => {
      const bytes =
        new Uint8Array(length);

      crypto.getRandomValues(
        bytes
      );

      let result = "";

      for (
        let i = 0;
        i < length;
        i++
      ) {
        result +=
          STAND_CHARS[
            bytes[i] %
              STAND_CHARS.length
          ];
      }

      return result;
    };

    const generateStandCode = (
      type = "QR"
    ) => {
      const prefix =
        type === "google_review"
          ? "GR"
          : type === "instagram"
          ? "IG"
          : "ST";

      return (
        prefix +
        "-" +
        randomChars(8)
      );
    };

    const generateUniqueStandCode =
      async (type) => {

        for (
          let attempt = 0;
          attempt < 20;
          attempt++
        ) {
          const code =
            generateStandCode(
              type
            );

          const existing =
            await env.DB
              .prepare(`
                SELECT id
                FROM stands
                WHERE stand_code = ?
                LIMIT 1
              `)
              .bind(code)
              .first();

          if (!existing) {
            return code;
          }
        }

        throw new Error(
          "Impossible de générer un code Stand unique."
        );
      };

    // =====================================================
    // GET STANDS
    // =====================================================

    if (
      url.pathname ===
        "/api/stands" &&
      request.method === "GET"
    ) {
      if (!(await isAdmin())) {
        return json(
          {
            success: false,
            error:
              "Non autorisé."
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
                  SELECT MAX(
                    ss.scanned_at
                  )
                  FROM stand_scans ss
                  WHERE ss.stand_code =
                    s.stand_code
                ) AS last_scan

              FROM stands s

              LEFT JOIN clients c
                ON s.client_id =
                   c.id

              ORDER BY s.id ASC
            `)
            .all();

        const stands =
          result.results.map(
            (stand) => ({
              ...stand,

              stand_type:
                String(
                  stand.stand_code ||
                  ""
                ).startsWith("GR-")
                  ? "google_review"
                  : String(
                      stand.stand_code ||
                      ""
                    ).startsWith("IG-")
                  ? "instagram"
                  : "stand",

              qr_url:
                `${url.origin}/r/${encodeURIComponent(
                  stand.stand_code
                )}`,

              nfc_url:
                `${url.origin}/r/${encodeURIComponent(
                  stand.stand_code
                )}`
            })
          );

        return json({
          success: true,
          total:
            stands.length,
          stands
        });

      } catch (error) {
        return json(
          {
            success: false,
            error:
              error.message
          },
          500
        );
      }
    }

    // =====================================================
    // BULK CREATE STANDS
    //
    // POST /api/stands/bulk
    //
    // Examples:
    //
    // {
    //   "google_review": 7,
    //   "instagram": 3
    // }
    //
    // or:
    //
    // {
    //   "count": 500
    // }
    // =====================================================

    if (
      url.pathname ===
        "/api/stands/bulk" &&
      request.method === "POST"
    ) {
      if (!(await isAdmin())) {
        return json(
          {
            success: false,
            error:
              "Non autorisé."
          },
          401
        );
      }

      try {
        const data =
          await request.json();

        let googleCount =
          Number(
            data.google_review || 0
          );

        let instagramCount =
          Number(
            data.instagram || 0
          );

        const genericCount =
          Number(
            data.count || 0
          );

        // Si count فقط موجود
        if (
          genericCount > 0 &&
          googleCount === 0 &&
          instagramCount === 0
        ) {
          googleCount =
            genericCount;
        }

        if (
          !Number.isInteger(
            googleCount
          ) ||
          !Number.isInteger(
            instagramCount
          ) ||
          googleCount < 0 ||
          instagramCount < 0
        ) {
          return json(
            {
              success: false,
              error:
                "Les quantités doivent être des nombres entiers positifs."
            },
            400
          );
        }

        const totalRequested =
          googleCount +
          instagramCount;

        if (
          totalRequested <= 0
        ) {
          return json(
            {
              success: false,
              error:
                "Indiquez au moins un Stand à créer."
            },
            400
          );
        }

        // حماية من طلبات ضخمة بالخطأ
        if (
          totalRequested > 5000
        ) {
          return json(
            {
              success: false,
              error:
                "Maximum 5000 Stands par opération."
            },
            400
          );
        }

        const created = [];

        // =================================================
        // GOOGLE REVIEW
        // =================================================

        for (
          let i = 0;
          i < googleCount;
          i++
        ) {
          const code =
            await generateUniqueStandCode(
              "google_review"
            );

          await env.DB
            .prepare(`
              INSERT INTO stands (
                stand_code,
                client_id,
                destination_url,
                status
              )
              VALUES (
                ?,
                NULL,
                NULL,
                'available'
              )
            `)
            .bind(code)
            .run();

          created.push({
            stand_code:
              code,

            stand_type:
              "google_review",

            status:
              "available",

            qr_url:
              `${url.origin}/r/${encodeURIComponent(
                code
              )}`,

            nfc_url:
              `${url.origin}/r/${encodeURIComponent(
                code
              )}`
          });
        }

        // =================================================
        // INSTAGRAM
        // =================================================

        for (
          let i = 0;
          i < instagramCount;
          i++
        ) {
          const code =
            await generateUniqueStandCode(
              "instagram"
            );

          await env.DB
            .prepare(`
              INSERT INTO stands (
                stand_code,
                client_id,
                destination_url,
                status
              )
              VALUES (
                ?,
                NULL,
                NULL,
                'available'
              )
            `)
            .bind(code)
            .run();

          created.push({
            stand_code:
              code,

            stand_type:
              "instagram",

            status:
              "available",

            qr_url:
              `${url.origin}/r/${encodeURIComponent(
                code
              )}`,

            nfc_url:
              `${url.origin}/r/${encodeURIComponent(
                code
              )}`
          });
        }

        return json({
          success: true,

          message:
            `${created.length} Stand(s) créé(s) avec succès.`,

          total:
            created.length,

          google_review:
            googleCount,

          instagram:
            instagramCount,

          stands:
            created
        });

      } catch (error) {
        return json(
          {
            success: false,
            error:
              error.message
          },
          500
        );
      }
    }

    // =====================================================
    // STAND BULK CSV
    // GET /api/stands/export
    // =====================================================

    if (
      url.pathname ===
        "/api/stands/export" &&
      request.method === "GET"
    ) {
      if (!(await isAdmin())) {
        return json(
          {
            success: false,
            error:
              "Non autorisé."
          },
          401
        );
      }

      try {
        const result =
          await env.DB
            .prepare(`
              SELECT
                id,
                stand_code,
                client_id,
                destination_url,
                status,
                created_at,
                activated_at
              FROM stands
              ORDER BY id ASC
            `)
            .all();

        const lines = [
          [
            "id",
            "stand_code",
            "stand_type",
            "qr_url",
            "status",
            "client_id",
            "destination_url",
            "created_at",
            "activated_at"
          ].join(",")
        ];

        for (
          const stand
          of result.results
        ) {
          const type =
            String(
              stand.stand_code ||
              ""
            ).startsWith("GR-")
              ? "google_review"
              : String(
                  stand.stand_code ||
                  ""
                ).startsWith("IG-")
              ? "instagram"
              : "stand";

          const qr =
            `${url.origin}/r/${encodeURIComponent(
              stand.stand_code
            )}`;

          const values = [
            stand.id,
            stand.stand_code,
            type,
            qr,
            stand.status,
            stand.client_id || "",
            stand.destination_url || "",
            stand.created_at || "",
            stand.activated_at || ""
          ];

          lines.push(
            values
              .map(
                (value) =>
                  `"${String(
                    value
                  ).replace(
                    /"/g,
                    '""'
                  )}"`
              )
              .join(",")
          );
        }

        return new Response(
          "\uFEFF" +
          lines.join("\n"),
          {
            status: 200,
            headers: {
              "Content-Type":
                "text/csv; charset=UTF-8",

              "Content-Disposition":
                'attachment; filename="tapnivo-stands.csv"'
            }
          }
        );

      } catch (error) {
        return json(
          {
            success: false,
            error:
              error.message
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
            error:
              "Non autorisé."
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
            ? Number(
                data.client_id
              )
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

        if (
          !isValidHttpUrl(
            destinationUrl
          )
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
            standCode,

          qr_url:
            `${url.origin}/r/${encodeURIComponent(
              standCode
            )}`
        });

      } catch (error) {
        return json(
          {
            success: false,
            error:
              error.message
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
            error:
              "Non autorisé."
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
            standCode,

          qr_url:
            `${url.origin}/r/${encodeURIComponent(
              standCode
            )}`
        });

      } catch (error) {
        return json(
          {
            success: false,
            error:
              error.message
          },
          500
        );
      }
    }

    // =====================================================
    // SERVICES HELPERS
    // =====================================================

    const generateServiceCode =
      () => {

        const chars =
          "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

        const bytes =
          new Uint8Array(8);

        crypto.getRandomValues(
          bytes
        );

        let code = "";

        for (
          let i = 0;
          i < 8;
          i++
        ) {
          code +=
            chars[
              bytes[i] %
                chars.length
            ];
        }

        return code;
      };

    // =====================================================
    // GET SERVICES
    // =====================================================

    if (
      url.pathname ===
        "/api/services" &&
      request.method === "GET"
    ) {
      if (!(await isAdmin())) {
        return json(
          {
            success: false,
            error:
              "Non autorisé."
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
                  WHERE ss.service_id =
                    s.id
                ) AS scans_count,

                (
                  SELECT COUNT(*)
                  FROM service_scans ss
                  WHERE ss.service_id =
                    s.id
                  AND date(
                    ss.scanned_at
                  ) = date('now')
                ) AS scans_today,

                (
                  SELECT COUNT(*)
                  FROM service_scans ss
                  WHERE ss.service_id =
                    s.id
                  AND ss.scanned_at >=
                    datetime(
                      'now',
                      '-7 days'
                    )
                ) AS scans_7_days,

                (
                  SELECT COUNT(*)
                  FROM service_scans ss
                  WHERE ss.service_id =
                    s.id
                  AND ss.scanned_at >=
                    datetime(
                      'now',
                      '-30 days'
                    )
                ) AS scans_30_days,

                (
                  SELECT MAX(
                    ss.scanned_at
                  )
                  FROM service_scans ss
                  WHERE ss.service_id =
                    s.id
                ) AS last_scan

              FROM services s

              LEFT JOIN clients c
                ON s.client_id =
                   c.id

              LEFT JOIN stands st
                ON s.stand_id =
                   st.id

              ORDER BY
                s.id DESC
            `)
            .all();

        const services =
          result.results.map(
            (service) => ({
              ...service,
              config:
                parseConfig(
                  service.config
                )
            })
          );

        return json({
          success: true,
          services
        });

      } catch (error) {
        return json(
          {
            success: false,
            error:
              error.message
          },
          500
        );
      }
    }

    // =====================================================
    // CREATE SERVICE
    // =====================================================

    if (
      url.pathname ===
        "/api/services" &&
      request.method === "POST"
    ) {
      if (!(await isAdmin())) {
        return json(
          {
            success: false,
            error:
              "Non autorisé."
          },
          401
        );
      }

      try {
        const data =
          await request.json();

        const clientId =
          Number(
            data.client_id
          );

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
            data.status ||
            "draft"
          ).trim();

        const standId =
          data.stand_id
            ? Number(
                data.stand_id
              )
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

        if (
          destinationUrl &&
          !isValidHttpUrl(
            destinationUrl
          )
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

        const config =
          data.config !==
            undefined &&
          data.config !== null
            ? typeof data.config ===
              "string"
              ? data.config
              : JSON.stringify(
                  data.config
                )
            : null;

        let serviceCode =
          "";

        for (
          let i = 0;
          i < 20;
          i++
        ) {
          const candidate =
            generateServiceCode();

          const exists =
           
