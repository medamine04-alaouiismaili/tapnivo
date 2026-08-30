export default {
  async fetch(request, env) {

    const url = new URL(request.url);

    // =====================================================
    // HELPERS
    // =====================================================

    const json = (
      data,
      status = 200,
      extraHeaders = {}
    ) => {

      return new Response(
        JSON.stringify(data, null, 2),
        {
          status,
          headers: {
            "Content-Type":
              "application/json; charset=UTF-8",

            "Cache-Control":
              "no-store",

            ...extraHeaders
          }
        }
      );

    };


    const html = (
      content,
      status = 200
    ) => {

      return new Response(
        content,
        {
          status,

          headers: {
            "Content-Type":
              "text/html; charset=UTF-8"
          }
        }
      );

    };


    const escapeHTML = (
      value
    ) => {

      if (
        value === null ||
        value === undefined
      ) {
        return "";
      }

      return String(value)

        .replace(
          /&/g,
          "&amp;"
        )

        .replace(
          /</g,
          "&lt;"
        )

        .replace(
          />/g,
          "&gt;"
        )

        .replace(
          /"/g,
          "&quot;"
        )

        .replace(
          /'/g,
          "&#039;"
        );

    };


    const getCookie = (
      request,
      name
    ) => {

      const cookieHeader =
        request.headers.get(
          "Cookie"
        );

      if (!cookieHeader) {
        return null;
      }

      for (
        const cookie
        of cookieHeader.split(";")
      ) {

        const parts =
          cookie.trim().split("=");

        if (
          parts[0] === name
        ) {

          return parts
            .slice(1)
            .join("=");

        }

      }

      return null;

    };


    const timingSafeEqual = (
      a,
      b
    ) => {

      if (
        a.length !== b.length
      ) {

        return false;

      }

      let result = 0;

      for (
        let i = 0;
        i < a.length;
        i++
      ) {

        result |=
          a[i] ^ b[i];

      }

      return result === 0;

    };


    const base64url = (
      input
    ) => {

      let binary = "";

      if (
        input instanceof Uint8Array
      ) {

        for (
          const byte
          of input
        ) {

          binary +=
            String.fromCharCode(
              byte
            );

        }

      } else {

        binary = input;

      }

      return btoa(binary)

        .replace(
          /\+/g,
          "-"
        )

        .replace(
          /\//g,
          "_"
        )

        .replace(
          /=+$/g,
          ""
        );

    };


    const fromBase64url = (
      input
    ) => {

      const padding =
        (
          4 -
          (
            input.length % 4
          )
        ) % 4;

      const base64 =
        input
          .replace(
            /-/g,
            "+"
          )
          .replace(
            /_/g,
            "/"
          ) +
        "=".repeat(
          padding
        );

      const binary =
        atob(base64);

      const bytes =
        new Uint8Array(
          binary.length
        );

      for (
        let i = 0;
        i < binary.length;
        i++
      ) {

        bytes[i] =
          binary.charCodeAt(i);

      }

      return bytes;

    };


    const parseConfig = (
      value
    ) => {

      if (!value) {
        return null;
      }

      if (
        typeof value ===
        "object"
      ) {

        return value;

      }

      try {

        return JSON.parse(
          value
        );

      } catch {

        return value;

      }

    };


    const isValidHttpUrl = (
      value
    ) => {

      if (!value) {
        return false;
      }

      try {

        const parsed =
          new URL(value);

        return (
          parsed.protocol ===
            "http:" ||
          parsed.protocol ===
            "https:"
        );

      } catch {

        return false;

      }

    };


    // =====================================================
    // SAFE PHONE
    // =====================================================

    const cleanPhone = (
      value
    ) => {

      return String(
        value || ""
      ).replace(
        /[^0-9+]/g,
        ""
      );

    };


    // =====================================================
    // ADMIN AUTH
    // =====================================================

    const createAdminToken =
      async () => {

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

            encoder.encode(
              env.ADMIN_KEY
            ),

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

              encoder.encode(
                timestamp
              )
            )
          );

        return (
          base64url(
            timestamp
          ) +
          "." +
          base64url(
            signature
          )
        );

      };


    const verifyAdminToken =
      async (
        token
      ) => {

        if (
          !token ||
          !env.ADMIN_KEY
        ) {

          return false;

        }

        const parts =
          token.split(".");

        if (
          parts.length !== 2
        ) {

          return false;

        }

        try {

          const timestampBytes =
            fromBase64url(
              parts[0]
            );

          const timestamp =
            new TextDecoder()
              .decode(
                timestampBytes
              );

          const time =
            Number(timestamp);

          if (
            !Number.isFinite(time)
          ) {

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

              encoder.encode(
                env.ADMIN_KEY
              ),

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

                encoder.encode(
                  timestamp
                )
              )
            );

          const received =
            fromBase64url(
              parts[1]
            );

          return timingSafeEqual(
            expected,
            received
          );

        } catch {

          return false;

        }

      };


    const isAdmin =
      async () => {

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
          password !==
            env.ADMIN_KEY
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
      url.pathname ===
      "/api/test-db"
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

            data.profession ||
              null,

            data.bio ||
              null,

            data.phone ||
              null,

            data.whatsapp ||
              null,

            data.email ||
              null,

            data.instagram ||
              null,

            data.facebook ||
              null,

            data.tiktok ||
              null,

            data.linkedin ||
              null,

            data.address ||
              null,

            data.maps ||
              null,

            data.website ||
              null,

            data.reviews ||
              null,

            data.photo_url ||
              null,

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


    const randomChars = (
      length = 8
    ) => {

      const bytes =
        new Uint8Array(
          length
        );

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
      type = "stand"
    ) => {

      const prefix =
        type ===
          "google_review"

          ? "GR"

          : type ===
              "instagram"

          ? "IG"

          : "ST";

      return (
        prefix +
        "-" +
        randomChars(8)
      );

    };


    const generateUniqueStandCode =
      async (
        type
      ) => {

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
    // END OF 1A
    // =====================================================

    // La suite 1B vient après ce bloc.    // =====================================================
    // GET STANDS
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

        const stands =
          result.results.map(
            (stand) => {

              const code =
                String(
                  stand.stand_code || ""
                );

              let standType = "stand";

              if (
                code.startsWith("GR-")
              ) {
                standType =
                  "google_review";
              }

              else if (
                code.startsWith("IG-")
              ) {
                standType =
                  "instagram";
              }

              return {
                ...stand,

                scans_count:
                  Number(
                    stand.scans_count || 0
                  ),

                stand_type:
                  standType,

                qr_url:
                  `${url.origin}/r/${encodeURIComponent(
                    code
                  )}`,

                nfc_url:
                  `${url.origin}/r/${encodeURIComponent(
                    code
                  )}`
              };

            }
          );

        return json({
          success: true,
          total: stands.length,
          stands
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
    // BULK CREATE STANDS
    // =====================================================
    //
    // POST /api/stands/bulk
    //
    // Examples:
    //
    // {
    //   "google_review": 20
    // }
    //
    // ou:
    //
    // {
    //   "instagram": 10
    // }
    //
    // ou:
    //
    // {
    //   "google_review": 20,
    //   "instagram": 10
    // }
    //
    // IMPORTANT:
    // Les Stands créés restent DISPONIBLES.
    // Ils ne sont liés à aucun client.
    //
    // =====================================================

    if (
      url.pathname === "/api/stands/bulk" &&
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


        // Si uniquement count est envoyé,
        // on crée des Stands génériques.

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


        // Protection contre les grosses erreurs

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
        // GOOGLE REVIEW STANDS
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
        // INSTAGRAM STANDS
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
            error: error.message
          },
          500
        );

      }

    }


    // =====================================================
    // EXPORT STANDS CSV
    // =====================================================

    if (
      url.pathname === "/api/stands/export" &&
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
            "nfc_url",
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

          const code =
            String(
              stand.stand_code || ""
            );


          const type =
            code.startsWith("GR-")
              ? "google_review"
              : code.startsWith("IG-")
              ? "instagram"
              : "stand";


          const qr =
            `${url.origin}/r/${encodeURIComponent(
              code
            )}`;


          const values = [

            stand.id,

            stand.stand_code,

            type,

            qr,

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
            error: error.message
          },
          500
        );

      }

    }


    // =====================================================
    // ACTIVATE STAND
    // =====================================================
    //
    // هنا Stand كيتربط فعلياً بالكليان.
    //
    // والأهم:
    // Stand ماشي هو Service.
    //
    // Stand عندو رابط /r/CODE
    // والرابط كيوصل للـ destination_url.
    //
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

            .bind(
              standCode
            )

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
          stand.status === "active"
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


        if (
          clientId !== null
        ) {

          const client =
            await env.DB

              .prepare(`
                SELECT id
                FROM clients
                WHERE id = ?
                LIMIT 1
              `)

              .bind(
                clientId
              )

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
            )}`,

          nfc_url:
            `${url.origin}/r/${encodeURIComponent(
              standCode
            )}`

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

            .bind(
              standCode
            )

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

          .bind(
            standCode
          )

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
            )}`,

          nfc_url:
            `${url.origin}/r/${encodeURIComponent(
              standCode
            )}`

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
    // END OF 1B
    // =====================================================
      // =====================================================
    // SERVICES HELPERS
    // =====================================================

    const generateServiceCode = () => {

      const chars =
        "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

      const bytes =
        new Uint8Array(8);

      crypto.getRandomValues(bytes);

      let code = "";

      for (let i = 0; i < 8; i++) {

        code +=
          chars[
            bytes[i] % chars.length
          ];

      }

      return code;

    };


    const generateUniqueServiceCode =
      async () => {

        for (
          let attempt = 0;
          attempt < 20;
          attempt++
        ) {

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
            return candidate;
          }

        }

        throw new Error(
          "Impossible de générer un code service unique."
        );

      };


    // =====================================================
    // GET SERVICES
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

                c.profession AS client_profession,

                c.photo_url AS client_photo_url,

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
                  AND ss.scanned_at >=
                    datetime('now','-7 days')
                ) AS scans_7_days,

                (
                  SELECT COUNT(*)
                  FROM service_scans ss
                  WHERE ss.service_id = s.id
                  AND ss.scanned_at >=
                    datetime('now','-30 days')
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
          result.results.map(
            service => ({

              ...service,

              scans_count:
                Number(
                  service.scans_count || 0
                ),

              scans_today:
                Number(
                  service.scans_today || 0
                ),

              scans_7_days:
                Number(
                  service.scans_7_days || 0
                ),

              scans_30_days:
                Number(
                  service.scans_30_days || 0
                ),

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
            data.status || "draft"
          ).trim();


        const standId =
          data.stand_id
            ? Number(data.stand_id)
            : null;


        // -------------------------------------------------
        // VALIDATION CLIENT
        // -------------------------------------------------

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


        const client =
          await env.DB

            .prepare(`
              SELECT
                id,
                name
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


        // -------------------------------------------------
        // TYPES AUTORISÉS
        // -------------------------------------------------

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


        // -------------------------------------------------
        // NOM SERVICE
        // -------------------------------------------------

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


        // -------------------------------------------------
        // STATUS
        // -------------------------------------------------

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


        // -------------------------------------------------
        // DESTINATION URL
        // -------------------------------------------------

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


        // -------------------------------------------------
        // STAND
        // -------------------------------------------------

        if (standId !== null) {

          const stand =
            await env.DB

              .prepare(`
                SELECT
                  id,
                  stand_code,
                  status,
                  client_id
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


          // ممنوع نربط Stand ديال client آخر

          if (
            stand.client_id !== null &&
            Number(stand.client_id) !==
              Number(clientId)
          ) {

            return json(
              {
                success: false,
                error:
                  "Ce Stand est déjà associé à un autre client."
              },
              409
            );

          }


          // Stand خاصو يكون available
          // أو أصلاً مربوط بنفس client

          if (
            stand.status === "active" &&
            Number(stand.client_id) !==
              Number(clientId)
          ) {

            return json(
              {
                success: false,
                error:
                  "Ce Stand est déjà actif pour un autre client."
              },
              409
            );

          }

        }


        // -------------------------------------------------
        // CONFIGURATION
        // -------------------------------------------------

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
                    "Configuration JSON invalide."
                },
                400
              );

            }

          } else {

            try {

              config =
                JSON.stringify(
                  data.config
                );

            } catch {

              return json(
                {
                  success: false,
                  error:
                    "Configuration impossible à enregistrer."
                },
                400
              );

            }

          }

        }


        // -------------------------------------------------
        // SERVICE CODE
        // -------------------------------------------------

        const serviceCode =
          await generateUniqueServiceCode();


        // -------------------------------------------------
        // ACTIVATION
        // -------------------------------------------------

        const activatedAt =
          status === "active"
            ? "CURRENT_TIMESTAMP"
            : "NULL";


        // -------------------------------------------------
        // INSERT SERVICE
        // -------------------------------------------------

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


        // -------------------------------------------------
        // SI SERVICE ACTIF AVEC STAND
        // LE STAND AUSSI DEVIENT ACTIF
        // -------------------------------------------------

        if (
          standId !== null &&
          status === "active"
        ) {

          await env.DB

            .prepare(`
              UPDATE stands

              SET
                client_id = ?,
                destination_url = ?,
                status = 'active',
                activated_at =
                  COALESCE(
                    activated_at,
                    CURRENT_TIMESTAMP
                  )

              WHERE id = ?
            `)

            .bind(

              clientId,

              `${url.origin}/s/${encodeURIComponent(
                serviceCode
              )}`,

              standId

            )

            .run();

        }


        return json({

          success: true,

          message:
            "Service créé avec succès.",

          service_code:
            serviceCode,

          qr_url:
            `${url.origin}/s/${encodeURIComponent(
              serviceCode
            )}`,

          nfc_url:
            `${url.origin}/s/${encodeURIComponent(
              serviceCode
            )}`

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
    // SERVICE ID
    // =====================================================

    const serviceIdMatch =
      url.pathname.match(
        /^\/api\/services\/(\d+)(?:\/stats)?$/
      );


    const serviceId =
      serviceIdMatch
        ? Number(
            serviceIdMatch[1]
          )
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

                s.status,

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
                    WHEN date(scanned_at) =
                      date('now')
                    THEN 1
                    ELSE 0
                  END
                ) AS today,

                SUM(
                  CASE
                    WHEN scanned_at >=
                      datetime(
                        'now',
                        '-7 days'
                      )
                    THEN 1
                    ELSE 0
                  END
                ) AS seven_days,

                SUM(
                  CASE
                    WHEN scanned_at >=
                      datetime(
                        'now',
                        '-30 days'
                      )
                    THEN 1
                    ELSE 0
                  END
                ) AS thirty_days,

                MAX(scanned_at)
                  AS last_scan

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


        // -------------------------------------------------
        // CLIENT
        // -------------------------------------------------

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "client_id"
          )
        ) {

          const value =
            Number(
              data.client_id
            );


          if (!value) {

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

              .bind(value)

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

          values.push(value);

        }


        // -------------------------------------------------
        // TYPE
        // -------------------------------------------------

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "service_type"
          )
        ) {

          const value =
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
            !allowedTypes.includes(
              value
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


          updates.push(
            "service_type = ?"
          );

          values.push(value);

        }


        // -------------------------------------------------
        // SERVICE NAME
        // -------------------------------------------------

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "service_name"
          )
        ) {

          const value =
            String(
              data.service_name || ""
            ).trim();


          if (!value) {

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

          values.push(value);

        }


        // -------------------------------------------------
        // DESTINATION
        // -------------------------------------------------

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "destination_url"
          )
        ) {

          const value =
            String(
              data.destination_url || ""
            ).trim();


          if (
            value &&
            !isValidHttpUrl(value)
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


          updates.push(
            "destination_url = ?"
          );

          values.push(
            value || null
          );

        }


        // -------------------------------------------------
        // STAND
        // -------------------------------------------------

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "stand_id"
          )
        ) {

          const value =
            data.stand_id
              ? Number(
                  data.stand_id
                )
              : null;


          if (value !== null) {

            const stand =
              await env.DB

                .prepare(`
                  SELECT
                    id,
                    client_id,
                    status
                  FROM stands
                  WHERE id = ?
                  LIMIT 1
                `)

                .bind(value)

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

          values.push(value);

        }


        // -------------------------------------------------
        // CONFIG
        // -------------------------------------------------

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "config"
          )
        ) {

          let value = null;


          if (
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

                value =
                  data.config;

              } catch {

                return json(
                  {
                    success: false,
                    error:
                      "Configuration JSON invalide."
                  },
                  400
                );

              }

            } else {

              value =
                JSON.stringify(
                  data.config
                );

            }

          }


          updates.push(
            "config = ?"
          );

          values.push(value);

        }


        // -------------------------------------------------
        // STATUS
        // -------------------------------------------------

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "status"
          )
        ) {

          const value =
            String(
              data.status || ""
            ).trim();


          if (
            ![
              "draft",
              "active",
              "inactive"
            ].includes(value)
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

          values.push(value);


          if (
            value === "active"
          ) {

            updates.push(
              "activated_at = COALESCE(activated_at, CURRENT_TIMESTAMP)"
            );

          } else {

            updates.push(
              "activated_at = NULL"
            );

          }

        }


        // -------------------------------------------------
        // NOTHING TO UPDATE
        // -------------------------------------------------

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


        values.push(
          serviceId
        );


        await env.DB

          .prepare(`
            UPDATE services

            SET
              ${updates.join(", ")}

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
              SELECT
                id,
                service_name
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


        // بسبب ON DELETE CASCADE
        // service_scans غادي يتحيدو بوحدهم.

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
    // END OF 1C
    // =====================================================
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
          "Service introuvable",
          404
        );

      }


      try {

        const service =
          await env.DB

            .prepare(`
              SELECT
                s.*,

                c.name AS client_name,
                c.profession AS client_profession,
                c.photo_url AS client_photo_url

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

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>TAPNIVO</title>

</head>

<body style="
font-family:Arial;
text-align:center;
padding:50px;
">

<h2>TAPNIVO</h2>

<h3>Service introuvable</h3>

<p>
Ce QR code n'existe pas.
</p>

</body>

</html>
`,
            404
          );

        }


        // -------------------------------------------------
        // SERVICE INACTIF
        // -------------------------------------------------

        if (
          service.status !== "active"
        ) {

          return html(
            `
<!DOCTYPE html>
<html lang="fr">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

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
padding:20px;
}

.box{
max-width:430px;
background:white;
padding:35px;
border-radius:22px;
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
Service indisponible
</h2>

<p>
Ce service n'est pas actuellement disponible.
</p>

</div>

</body>

</html>
`
          );

        }


        // -------------------------------------------------
        // ENREGISTRER LE SCAN
        // -------------------------------------------------

        await env.DB

          .prepare(`
            INSERT INTO service_scans (
              service_id
            )

            VALUES (?)
          `)

          .bind(
            service.id
          )

          .run();


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

              ? (
                  config.wifi_name ||
                  config.ssid ||
                  ""
                )

              : "";


          const password =
            config &&
            typeof config === "object"

              ? (
                  config.password ||
                  ""
                )

              : "";


          const security =
            config &&
            typeof config === "object"

              ? (
                  config.security ||
                  "WPA"
                )

              : "WPA";


          return html(`
<!DOCTYPE html>

<html lang="fr">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>
${escapeHTML(
  service.service_name
)}
</title>


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

font-family:
Arial,
Helvetica,
sans-serif;

background:
linear-gradient(
135deg,
#f5f7fb,
#eef2ff
);

padding:20px;

}

.box{

width:100%;

max-width:430px;

background:white;

border-radius:25px;

padding:30px;

text-align:center;

box-shadow:
0 15px 45px
rgba(0,0,0,.09);

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

border-bottom:
1px solid #e5e7eb;

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
`);

        }


        // =================================================
        // GOOGLE REVIEW / MENU / CUSTOM LINK
        // =================================================

        if (
          [
            "google_review",
            "menu",
            "custom_link"
          ].includes(
            service.service_type
          )
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

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>TAPNIVO</title>

</head>

<body style="
font-family:Arial;
text-align:center;
padding:50px;
">

<h2>
TAPNIVO
</h2>

<p>
Aucune destination configurée.
</p>

</body>

</html>
`
          );

        }


        // =================================================
        // DIGITAL BUSINESS CARD
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

              .bind(
                service.client_id
              )

              .first();


          if (!client) {

            return html(
              "Client introuvable",
              404
            );

          }


          // ------------------------------------------------
          // DONNÉES CLIENT
          // ------------------------------------------------

          const name =
            client.name || "";


          const profession =
            client.profession || "";


          const bio =
            client.bio || "";


          const phone =
            client.phone || "";


          const whatsapp =
            client.whatsapp || "";


          const email =
            client.email || "";


          const instagram =
            client.instagram || "";


          const facebook =
            client.facebook || "";


          const tiktok =
            client.tiktok || "";


          const linkedin =
            client.linkedin || "";


          const maps =
            client.maps || "";


          const website =
            client.website || "";


          const reviews =
            client.reviews || "";


          const address =
            client.address || "";


          const photo =
            client.photo_url || "";


          // ------------------------------------------------
          // WHATSAPP
          // ------------------------------------------------

          const whatsappNumber =
            whatsapp.replace(
              /[^0-9]/g,
              ""
            );


          // ------------------------------------------------
          // VCF / CONTACT
          //
          // الرابط غادي يكون:
          //
          // /contact/SERVICECODE.vcf
          //
          // وبهاد الطريقة:
          //
          // Ajouter aux contacts
          //
          // يقدر يحفظ الاسم والهاتف والإيميل
          // وWhatsApp والموقع والصورة.
          // ------------------------------------------------

          const contactUrl =
            `${url.origin}/contact/${encodeURIComponent(
              service.service_code
            )}.vcf`;


          // ------------------------------------------------
          // BUTTONS
          // ------------------------------------------------

          const buttons = [];


          if (phone) {

            buttons.push(`
<a
class="button"
href="tel:${escapeHTML(
  phone
)}"
>
📞 Appeler
</a>
`);

          }


          if (
            whatsappNumber
          ) {

            buttons.push(`
<a
class="button"
href="https://wa.me/${escapeHTML(
  whatsappNumber
)}"
target="_blank"
rel="noopener"
>
💬 WhatsApp
</a>
`);

          }


          // IMPORTANT:
          // Ajouter aux contacts
          // ------------------------------------------------

          buttons.push(`
<a
class="button contact"
href="${escapeHTML(
  contactUrl
)}"
>
👤 Ajouter aux contacts
</a>
`);


          if (email) {

            buttons.push(`
<a
class="button secondary"
href="mailto:${escapeHTML(
  email
)}"
>
✉️ Email
</a>
`);

          }


          if (instagram) {

            buttons.push(`
<a
class="button secondary"
href="${escapeHTML(
  instagram
)}"
target="_blank"
rel="noopener"
>
📸 Instagram
</a>
`);

          }


          if (facebook) {

            buttons.push(`
<a
class="button secondary"
href="${escapeHTML(
  facebook
)}"
target="_blank"
rel="noopener"
>
📘 Facebook
</a>
`);

          }


          if (tiktok) {

            buttons.push(`
<a
class="button secondary"
href="${escapeHTML(
  tiktok
)}"
target="_blank"
rel="noopener"
>
🎵 TikTok
</a>
`);

          }


          if (linkedin) {

            buttons.push(`
<a
class="button secondary"
href="${escapeHTML(
  linkedin
)}"
target="_blank"
rel="noopener"
>
💼 LinkedIn
</a>
`);

          }


          if (maps) {

            buttons.push(`
<a
class="button secondary"
href="${escapeHTML(
  maps
)}"
target="_blank"
rel="noopener"
>
📍 Google Maps
</a>
`);

          }


          if (website) {

            buttons.push(`
<a
class="button secondary"
href="${escapeHTML(
  website
)}"
target="_blank"
rel="noopener"
>
🌐 Site web
</a>
`);

          }


          if (reviews) {

            buttons.push(`
<a
class="button secondary"
href="${escapeHTML(
  reviews
)}"
target="_blank"
rel="noopener"
>
⭐ Google Reviews
</a>
`);

          }


          // ------------------------------------------------
          // PHOTO
          // ------------------------------------------------

          const photoHTML =
            photo

              ? `
<img
class="profile-photo"
src="${escapeHTML(
  photo
)}"
alt="${escapeHTML(
  name
)}"
loading="lazy"
>
`

              : `
<div class="avatar">
👤
</div>
`;


          // ------------------------------------------------
          // RETURN CARD
          // ------------------------------------------------

          return html(`
<!DOCTYPE html>

<html lang="fr">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<meta
name="theme-color"
content="#4f46e5"
>

<title>
${escapeHTML(
  name
)} | TAPNIVO
</title>


<style>

*{
box-sizing:border-box;
}


body{

margin:0;

font-family:
Arial,
Helvetica,
sans-serif;

background:
linear-gradient(
135deg,
#f5f7fb,
#eef2ff
);

color:#111827;

min-height:100vh;

}


.container{

max-width:560px;

margin:auto;

padding:30px 18px 45px;

}


.card{

background:white;

border-radius:28px;

padding:30px 22px;

text-align:center;

box-shadow:
0 18px 50px
rgba(0,0,0,.09);

}


.logo{

font-size:21px;

font-weight:800;

margin-bottom:25px;

letter-spacing:.5px;

}


.logo span{

color:#4f46e5;

}


.profile-photo{

width:115px;

height:115px;

border-radius:50%;

object-fit:cover;

display:block;

margin:0 auto 18px;

border:
4px solid #eef2ff;

}


.avatar{

width:115px;

height:115px;

border-radius:50%;

margin:0 auto 18px;

background:#eef2ff;

display:flex;

align-items:center;

justify-content:center;

font-size:45px;

}


h1{

margin:0;

font-size:28px;

line-height:1.2;

}


.profession{

color:#4f46e5;

font-weight:700;

margin-top:8px;

}


.bio{

color:#6b7280;

line-height:1.65;

margin:18px 0;

}


.buttons{

display:grid;

gap:10px;

margin-top:24px;

}


.button{

display:block;

width:100%;

padding:14px;

border-radius:13px;

text-decoration:none;

font-weight:700;

background:#4f46e5;

color:white;

}


.button.contact{

background:#111827;

}


.button.secondary{

background:#f3f4f6;

color:#374151;

}


.info{

margin-top:25px;

text-align:left;

}


.info-row{

padding:13px 0;

border-bottom:
1px solid #eeeeee;

}


.info-row:last-child{

border-bottom:0;

}


.label{

font-size:11px;

color:#9ca3af;

margin-bottom:4px;

}


.value{

font-weight:600;

word-break:break-word;

}


.footer{

margin-top:25px;

color:#9ca3af;

font-size:11px;

}


</style>

</head>


<body>


<div class="container">


<div class="card">


<div class="logo">

TAP<span>NIVO</span>

</div>


${photoHTML}


<h1>

${escapeHTML(
  name
)}

</h1>


${
  profession

    ? `

<div class="profession">

${escapeHTML(
  profession
)}

</div>

`

    : ""
}


${
  bio

    ? `

<div class="bio">

${escapeHTML(
  bio
)}

</div>

`

    : ""
}


<div class="buttons">

${buttons.join("")}

</div>


<div class="info">


${
  address

    ? `

<div class="info-row">

<div class="label">
Adresse
</div>

<div class="value">

${escapeHTML(
  address
)}

</div>

</div>

`

    : ""
}


${
  email

    ? `

<div class="info-row">

<div class="label">
Email
</div>

<div class="value">

${escapeHTML(
  email
)}

</div>

</div>

`

    : ""
}


${
  phone

    ? `

<div class="info-row">

<div class="label">
Téléphone
</div>

<div class="value">

${escapeHTML(
  phone
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
`);

        }


        // =================================================
        // SERVICE INCONNU
        // =================================================

        return html(
          `
<!DOCTYPE html>

<html lang="fr">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>TAPNIVO</title>

</head>

<body style="
font-family:Arial;
text-align:center;
padding:50px;
">

<h2>
TAPNIVO
</h2>

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

<title>
TAPNIVO
</title>

</head>

<body style="
font-family:Arial;
text-align:center;
padding:50px;
">

<h2>
Erreur serveur
</h2>

<p>
${escapeHTML(
  error.message
)}
</p>

</body>

</html>
`,
          500
        );

      }

    }


    // =====================================================
    // CONTACT / VCF
    //
    // /contact/SERVICECODE.vcf
    //
    // كيولد Contact مباشرة من معلومات Client
    //
    // =====================================================

    if (
      url.pathname.startsWith(
        "/contact/"
      ) &&
      url.pathname.endsWith(".vcf")
    ) {

      const serviceCode =
        url.pathname
          .replace(
            "/contact/",
            ""
          )
          .replace(
            /\.vcf$/,
            ""
          )
          .trim();


      if (!serviceCode) {

        return new Response(
          "Contact introuvable.",
          {
            status:404,
            headers:{
              "Content-Type":
                "text/plain; charset=UTF-8"
            }
          }
        );

      }


      try {

        const service =
          await env.DB

            .prepare(`
              SELECT
                s.id,
                s.service_code,
                s.service_type,
                s.status,
                s.client_id

              FROM services s

              WHERE s.service_code = ?

              LIMIT 1
            `)

            .bind(
              serviceCode
            )

            .first();


        if (!service) {

          return new Response(
            "Service introuvable.",
            {
              status:404,
              headers:{
                "Content-Type":
                  "text/plain; charset=UTF-8"
              }
            }
          );

        }


        if (
          service.status !==
          "active"
        ) {

          return new Response(
            "Service indisponible.",
            {
              status:404,
              headers:{
                "Content-Type":
                  "text/plain; charset=UTF-8"
              }
            }
          );

        }


        const client =
          await env.DB

            .prepare(`
              SELECT *

              FROM clients

              WHERE id = ?

              LIMIT 1
            `)

            .bind(
              service.client_id
            )

            .first();


        if (!client) {

          return new Response(
            "Client introuvable.",
            {
              status:404,
              headers:{
                "Content-Type":
                  "text/plain; charset=UTF-8"
              }
            }
          );

        }


        // ------------------------------------------------
        // VCF ESCAPE
        // ------------------------------------------------

        const vcfEscape =
          (value) => {

            if (
              value === null ||
              value === undefined
            ) {

              return "";

            }


            return String(value)

              .replace(
                /\\/g,
                "\\\\"
              )

              .replace(
                /\n/g,
                "\\n"
              )

              .replace(
                /;/g,
                "\\;"
              )

              .replace(
                /,/g,
                "\\,"
              );

          };


        const name =
          vcfEscape(
            client.name || ""
          );


        const phone =
          vcfEscape(
            client.phone || ""
          );


        const whatsapp =
          vcfEscape(
            client.whatsapp || ""
          );


        const email =
          vcfEscape(
            client.email || ""
          );


        const website =
          vcfEscape(
            client.website || ""
          );


        const address =
          vcfEscape(
            client.address || ""
          );


        const profession =
          vcfEscape(
            client.profession || ""
          );


        const photo =
          client.photo_url
            ? String(
                client.photo_url
              ).trim()
            : "";


        const lines = [

          "BEGIN:VCARD",

          "VERSION:3.0",

          `FN:${name}`,

          `N:${name};;;;`

        ];


        if (phone) {

          lines.push(
            `TEL;TYPE=CELL:${phone}`
          );

        }


        if (whatsapp) {

          lines.push(
            `item1.X-ABLABEL:WhatsApp`
          );

          lines.push(
            `item1.X-ABRELATEDNAMES:${whatsapp}`
          );

        }


        if (email) {

          lines.push(
            `EMAIL;TYPE=INTERNET:${email}`
          );

        }


        if (profession) {

          lines.push(
            `TITLE:${profession}`
          );

        }


        if (website) {

          lines.push(
            `URL:${website}`
          );

        }


        if (address) {

          lines.push(
            `ADR;TYPE=WORK:;;${address};;;;`
          );

        }


        if (photo) {

          // إذا كانت الصورة URL،
          // نحطها كرابط فـ vCard.
          //
          // بعض الهواتف غادي تحملها،
          // وبعضها يقدر ما يدعمش URL للصورة.

          lines.push(
            `PHOTO;VALUE=URI:${photo}`
          );

        }


        lines.push(
          "END:VCARD"
        );


        const vcard =
          lines.join("\r\n");


        return new Response(
          vcard,
          {

            status:200,

            headers:{

              "Content-Type":
                "text/vcard; charset=UTF-8",

              "Content-Disposition":
                `attachment; filename="${encodeURIComponent(
                  client.name || "contact"
                )}.vcf"`,

              "Cache-Control":
                "no-store"

            }

          }
        );


      } catch (error) {

        return new Response(
          "Erreur serveur : " +
          error.message,
          {
            status:500,
            headers:{
              "Content-Type":
                "text/plain; charset=UTF-8"
            }
          }
        );

      }

    }


    // =====================================================
    // END OF 1D
    // =====================================================
      // =====================================================
    // EXISTING STAND DYNAMIC QR
    // /r/STANDCODE
    //
    // نفس QR / NFC كيبقى ثابت
    // والوجهة كتبدل من Dashboard
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
                s.stand_code,
                s.destination_url,
                s.status,
                s.client_id,

                c.name AS client_name

              FROM stands s

              LEFT JOIN clients c
                ON s.client_id = c.id

              WHERE s.stand_code = ?

              LIMIT 1
            `)

            .bind(
              standCode
            )

            .first();


        // -------------------------------------------------
        // STAND NOT FOUND
        // -------------------------------------------------

        if (!stand) {

          return html(
            `
<!DOCTYPE html>

<html lang="fr">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

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

padding:20px;

}

.box{

background:white;

padding:35px;

border-radius:22px;

box-shadow:
0 15px 40px
rgba(0,0,0,.08);

max-width:420px;

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
Stand introuvable
</h2>

<p>
Ce QR code ou NFC n'est pas reconnu.
</p>

</div>

</body>

</html>
`,
            404
          );

        }


        // -------------------------------------------------
        // STAND AVAILABLE
        // -------------------------------------------------

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

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>
TAPNIVO
</title>


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

font-family:
Arial,
Helvetica,
sans-serif;

background:
linear-gradient(
135deg,
#f5f7fb,
#eef2ff
);

padding:20px;

text-align:center;

}


.box{

width:100%;

max-width:430px;

background:white;

padding:35px 25px;

border-radius:25px;

box-shadow:
0 18px 45px
rgba(0,0,0,.08);

}


.logo{

font-size:24px;

font-weight:800;

margin-bottom:25px;

}


.logo span{

color:#4f46e5;

}


.icon{

font-size:55px;

margin-bottom:15px;

}


h2{

margin:0 0 10px;

}


p{

color:#6b7280;

line-height:1.6;

}


.code{

display:inline-block;

margin-top:15px;

padding:9px 13px;

border-radius:9px;

background:#eef2ff;

color:#3730a3;

font-size:13px;

font-weight:bold;

}

</style>

</head>


<body>


<div class="box">


<div class="logo">
TAP<span>NIVO</span>
</div>


<div class="icon">
📲
</div>


<h2>
Stand prêt à être activé
</h2>


<p>

هذا الـStand مازال ما تربطش
بأي Client.

</p>


<div class="code">

${escapeHTML(
  stand.stand_code
)}

</div>


</div>


</body>

</html>
`
          );

        }


        // -------------------------------------------------
        // REGISTER STAND SCAN
        // -------------------------------------------------

        await env.DB

          .prepare(`
            INSERT INTO stand_scans (
              stand_code
            )

            VALUES (?)
          `)

          .bind(
            standCode
          )

          .run();


        // -------------------------------------------------
        // REDIRECT
        // -------------------------------------------------

        return Response.redirect(
          stand.destination_url,
          302
        );


      } catch (error) {

        return html(
          `
<!DOCTYPE html>

<html lang="fr">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>
TAPNIVO
</title>

</head>


<body style="
font-family:Arial;
text-align:center;
padding:50px;
">

<h2>
Erreur serveur
</h2>

<p>
${escapeHTML(
  error.message
)}
</p>

</body>

</html>
`,
          500
        );

      }

    }


    // =====================================================
    // CLIENT PROFILE
    // /client/SLUG
    //
    // Profil public للعميل
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
          .replace(
            /\/$/,
            ""
          )
          .trim();


      if (!slug) {

        return html(
          "Profil introuvable",
          404
        );

      }


      try {

        const client =
          await env.DB

            .prepare(`
              SELECT *
              FROM clients
              WHERE slug = ?
              LIMIT 1
            `)

            .bind(
              slug
            )

            .first();


        if (!client) {

          return html(
            "Client introuvable",
            404
          );

        }


        // -------------------------------------------------
        // PUBLIC CLIENT PROFILE
        // -------------------------------------------------

        const photoHTML =
          client.photo_url

            ? `

<img
class="profile-photo"
src="${escapeHTML(
  client.photo_url
)}"
alt="${escapeHTML(
  client.name
)}"
loading="lazy"
>

`

            : `

<div class="avatar">
👤
</div>

`;


        const buttons = [];


        if (client.phone) {

          buttons.push(`

<a
class="button"
href="tel:${escapeHTML(
  client.phone
)}"
>

📞 Appeler

</a>

`);

        }


        if (client.whatsapp) {

          const whatsapp =
            String(
              client.whatsapp
            ).replace(
              /[^0-9]/g,
              ""
            );


          buttons.push(`

<a
class="button"
href="https://wa.me/${escapeHTML(
  whatsapp
)}"
target="_blank"
rel="noopener"
>

💬 WhatsApp

</a>

`);

        }


        // -------------------------------------------------
        // ADD CONTACT
        // -------------------------------------------------

        /*
         *
         * Client profile عندو حتى هو
         * Ajouter aux contacts.
         *
         */

        const contactUrl =
          `${url.origin}/contact/client/${encodeURIComponent(
            client.slug
          )}.vcf`;


        buttons.push(`

<a
class="button contact"
href="${escapeHTML(
  contactUrl
)}"
>

👤 Ajouter aux contacts

</a>

`);


        if (client.email) {

          buttons.push(`

<a
class="button secondary"
href="mailto:${escapeHTML(
  client.email
)}"
>

✉️ Email

</a>

`);

        }


        if (client.instagram) {

          buttons.push(`

<a
class="button secondary"
href="${escapeHTML(
  client.instagram
)}"
target="_blank"
rel="noopener"
>

📸 Instagram

</a>

`);

        }


        if (client.facebook) {

          buttons.push(`

<a
class="button secondary"
href="${escapeHTML(
  client.facebook
)}"
target="_blank"
rel="noopener"
>

📘 Facebook

</a>

`);

        }


        if (client.tiktok) {

          buttons.push(`

<a
class="button secondary"
href="${escapeHTML(
  client.tiktok
)}"
target="_blank"
rel="noopener"
>

🎵 TikTok

</a>

`);

        }


        if (client.linkedin) {

          buttons.push(`

<a
class="button secondary"
href="${escapeHTML(
  client.linkedin
)}"
target="_blank"
rel="noopener"
>

💼 LinkedIn

</a>

`);

        }


        if (client.maps) {

          buttons.push(`

<a
class="button secondary"
href="${escapeHTML(
  client.maps
)}"
target="_blank"
rel="noopener"
>

📍 Google Maps

</a>

`);

        }


        if (client.website) {

          buttons.push(`

<a
class="button secondary"
href="${escapeHTML(
  client.website
)}"
target="_blank"
rel="noopener"
>

🌐 Site web

</a>

`);

        }


        if (client.reviews) {

          buttons.push(`

<a
class="button secondary"
href="${escapeHTML(
  client.reviews
)}"
target="_blank"
rel="noopener"
>

⭐ Google Reviews

</a>

`);

        }


        return html(`

<!DOCTYPE html>

<html lang="fr">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<meta
name="theme-color"
content="#4f46e5"
>


<title>

${escapeHTML(
  client.name
)}

| TAPNIVO

</title>


<style>

*{

box-sizing:border-box;

}


body{

margin:0;

font-family:
Arial,
Helvetica,
sans-serif;

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

padding:35px 18px 45px;

}


.profile{

background:white;

border-radius:28px;

padding:30px 22px;

text-align:center;

box-shadow:
0 18px 50px
rgba(0,0,0,.09);

}


.logo{

font-size:21px;

font-weight:800;

margin-bottom:28px;

}


.logo span{

color:#4f46e5;

}


.profile-photo{

width:120px;

height:120px;

border-radius:50%;

object-fit:cover;

display:block;

margin:0 auto 20px;

border:
4px solid #eef2ff;

}


.avatar{

width:120px;

height:120px;

border-radius:50%;

margin:0 auto 20px;

background:#eef2ff;

display:flex;

align-items:center;

justify-content:center;

font-size:48px;

}


h1{

margin:0;

font-size:29px;

}


.profession{

color:#4f46e5;

font-weight:bold;

margin-top:8px;

}


.bio{

color:#6b7280;

line-height:1.65;

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

border-radius:13px;

text-decoration:none;

font-weight:bold;

background:#4f46e5;

color:white;

}


.button.contact{

background:#111827;

}


.button.secondary{

background:#f3f4f6;

color:#374151;

}


.info{

margin-top:25px;

text-align:left;

}


.info-row{

padding:13px 0;

border-bottom:
1px solid #eeeeee;

}


.label{

font-size:11px;

color:#9ca3af;

}


.value{

margin-top:5px;

font-weight:600;

word-break:break-word;

}


.footer{

margin-top:25px;

font-size:11px;

color:#9ca3af;

}

</style>

</head>


<body>


<div class="container">


<div class="profile">


<div class="logo">

TAP<span>NIVO</span>

</div>


${photoHTML}


<h1>

${escapeHTML(
  client.name
)}

</h1>


${
  client.profession

    ? `

<div class="profession">

${escapeHTML(
  client.profession
)}

</div>

`

    : ""
}


${
  client.bio

    ? `

<div class="bio">

${escapeHTML(
  client.bio
)}

</div>

`

    : ""
}


<div class="buttons">

${buttons.join("")}

</div>


<div class="info">


${
  client.email

    ? `

<div class="info-row">

<div class="label">
Email
</div>

<div class="value">

${escapeHTML(
  client.email
)}

</div>

</div>

`

    : ""
}


${
  client.phone

    ? `

<div class="info-row">

<div class="label">
Téléphone
</div>

<div class="value">

${escapeHTML(
  client.phone
)}

</div>

</div>

`

    : ""
}


${
  client.address

    ? `

<div class="info-row">

<div class="label">
Adresse
</div>

<div class="value">

${escapeHTML(
  client.address
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

`);


      } catch (error) {

        return html(
          "Erreur serveur : " +
          escapeHTML(
            error.message
          ),
          500
        );

      }

    }


    // =====================================================
    // CLIENT CONTACT / VCF
    //
    // /contact/client/SLUG.vcf
    //
    // =====================================================

    if (
      url.pathname.startsWith(
        "/contact/client/"
      ) &&
      url.pathname.endsWith(
        ".vcf"
      )
    ) {

      const slug =
        url.pathname

          .replace(
            "/contact/client/",
            ""
          )

          .replace(
            /\.vcf$/,
            ""
          )

          .trim();


      if (!slug) {

        return new Response(
          "Contact introuvable.",
          {
            status:404,

            headers:{
              "Content-Type":
                "text/plain; charset=UTF-8"
            }
          }
        );

      }


      try {

        const client =
          await env.DB

            .prepare(`
              SELECT *
              FROM clients
              WHERE slug = ?
              LIMIT 1
            `)

            .bind(
              slug
            )

            .first();


        if (!client) {

          return new Response(
            "Client introuvable.",
            {
              status:404,

              headers:{
                "Content-Type":
                  "text/plain; charset=UTF-8"
              }
            }
          );

        }


        const vcfEscape =
          (value) => {

            if (
              value === null ||
              value === undefined
            ) {

              return "";

            }


            return String(value)

              .replace(
                /\\/g,
                "\\\\"
              )

              .replace(
                /\n/g,
                "\\n"
              )

              .replace(
                /;/g,
                "\\;"
              )

              .replace(
                /,/g,
                "\\,"
              );

          };


        const name =
          vcfEscape(
            client.name || ""
          );


        const phone =
          vcfEscape(
            client.phone || ""
          );


        const whatsapp =
          vcfEscape(
            client.whatsapp || ""
          );


        const email =
          vcfEscape(
            client.email || ""
          );


        const website =
          vcfEscape(
            client.website || ""
          );


        const address =
          vcfEscape(
            client.address || ""
          );


        const profession =
          vcfEscape(
            client.profession || ""
          );


        const photo =
          client.photo_url
            ? String(
                client.photo_url
              ).trim()
            : "";


        const lines = [

          "BEGIN:VCARD",

          "VERSION:3.0",

          `FN:${name}`,

          `N:${name};;;;`

        ];


        if (phone) {

          lines.push(
            `TEL;TYPE=CELL:${phone}`
          );

        }


        if (email) {

          lines.push(
            `EMAIL;TYPE=INTERNET:${email}`
          );

        }


        if (profession) {

          lines.push(
            `TITLE:${profession}`
          );

        }


        if (address) {

          lines.push(
            `ADR;TYPE=WORK:;;${address};;;;`
          );

        }


        if (website) {

          lines.push(
            `URL:${website}`
          );

        }


        if (whatsapp) {

          lines.push(
            `item1.X-ABLABEL:WhatsApp`
          );

          lines.push(
            `item1.X-ABRELATEDNAMES:${whatsapp}`
          );

        }


        if (photo) {

          lines.push(
            `PHOTO;VALUE=URI:${photo}`
          );

        }


        lines.push(
          "END:VCARD"
        );


        const vcard =
          lines.join(
            "\r\n"
          );


        return new Response(
          vcard,
          {

            status:200,

            headers:{

              "Content-Type":
                "text/vcard; charset=UTF-8",

              "Content-Disposition":
                `attachment; filename="${encodeURIComponent(
                  client.name ||
                  "contact"
                )}.vcf"`,

              "Cache-Control":
                "no-store"

            }

          }
        );


      } catch (error) {

        return new Response(
          "Erreur serveur : " +
          error.message,
          {

            status:500,

            headers:{
              "Content-Type":
                "text/plain; charset=UTF-8"
            }

          }
        );

      }

    }


    // =====================================================
    // STATIC FILES
    // =====================================================

    return env.ASSETS.fetch(
      request
    );

  }

};
