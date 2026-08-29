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
        const timestampBytes = fromBase64url(parts[0]);

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

        const expected = new Uint8Array(
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
            ) +
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
    // GET ALL STANDS + SCAN STATISTICS
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
                ) AS last_scan_at

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
    // GET SCANS FOR ONE STAND
    // =====================================================

    if (
      url.pathname === "/api/stands/scans" &&
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
        const standCode =
          String(
            url.searchParams.get(
              "stand_code"
            ) || ""
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

        const result =
          await env.DB
            .prepare(`
              SELECT
                id,
                stand_code,
                scanned_at
              FROM stand_scans
              WHERE stand_code = ?
              ORDER BY id DESC
            `)
            .bind(standCode)
            .all();

        return json({
          success: true,
          stand_code: standCode,
          scans: result.results,
          scans_count: result.results.length
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
    // DYNAMIC QR / NFC
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
          {
            status: 404
          }
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
            {
              status: 404
            }
          );
        }

        // =================================================
        // STAND NON ACTIVE
        // =================================================

        if (
          stand.status !== "active" ||
          !stand.destination_url
        ) {
          return new Response(
            `
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
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
Stand non activé
</h2>

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

        // =================================================
        // ENREGISTRER LE SCAN
        // =================================================

        await env.DB
          .prepare(`
            INSERT INTO stand_scans (
              stand_code,
              scanned_at
            )
            VALUES (
              ?,
              CURRENT_TIMESTAMP
            )
          `)
          .bind(standCode)
          .run();

        // =================================================
        // REDIRECTION
        // =================================================

        return Response.redirect(
          stand.destination_url,
          302
        );

      } catch (error) {
        return new Response(
          "Erreur serveur : " +
          error.message,
          {
            status: 500
          }
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
          .replace(/\/$/, "");

      if (!slug) {
        return new Response(
          "Profil introuvable",
          {
            status: 404
          }
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
            {
              status: 404
            }
          );
        }

        const escapeHTML = (value) => {
          if (!value) {
            return "";
          }

          return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
        };

        const html = `
<!DOCTYPE html>

<html lang="fr">

<head>

<meta charset="UTF-8">

<meta
  name="viewport"
  content="width=device-width, initial-scale=1.0"
>

<title>
${escapeHTML(result.name)} | TAPNIVO
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

  padding:40px 20px;
}

.profile{
  background:white;

  border-radius:25px;

  padding:35px 25px;

  text-align:center;

  box-shadow:
    0 15px 40px
    rgba(0,0,0,0.08);
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

  margin:
    auto auto 20px;

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

  border-bottom:
    1px solid #eee;
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
${escapeHTML(result.name)}
</h1>

${
  result.profession
    ? `
<div class="profession">
${escapeHTML(result.profession)}
</div>
`
    : ""
}

${
  result.bio
    ? `
<div class="bio">
${escapeHTML(result.bio)}
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
  href="tel:${escapeHTML(result.phone)}"
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
  href="${escapeHTML(result.instagram)}"
  target="_blank"
>
Instagram
</a>
`
    : ""
}

${
  result.facebook
    ? `
<a
  class="button secondary"
  href="${escapeHTML(result.facebook)}"
  target="_blank"
>
Facebook
</a>
`
    : ""
}

${
  result.tiktok
    ? `
<a
  class="button secondary"
  href="${escapeHTML(result.tiktok)}"
  target="_blank"
>
TikTok
</a>
`
    : ""
}

${
  result.linkedin
    ? `
<a
  class="button secondary"
  href="${escapeHTML(result.linkedin)}"
  target="_blank"
>
LinkedIn
</a>
`
    : ""
}

${
  result.maps
    ? `
<a
  class="button secondary"
  href="${escapeHTML(result.maps)}"
  target="_blank"
>
📍 Google Maps
</a>
`
    : ""
}

${
  result.website
    ? `
<a
  class="button secondary"
  href="${escapeHTML(result.website)}"
  target="_blank"
>
🌐 Site web
</a>
`
    : ""
}

${
  result.reviews
    ? `
<a
  class="button secondary"
  href="${escapeHTML(result.reviews)}"
  target="_blank"
>
⭐ Google Reviews
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
${escapeHTML(result.email)}
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
${escapeHTML(result.address)}
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
          {
            status: 500
          }
        );
      }
    }

    // =====================================================
    // STATIC FILES
    // =====================================================

    return env.ASSETS.fetch(request);
  }
};
