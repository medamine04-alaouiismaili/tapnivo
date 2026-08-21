export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // =========================
    // TEST DATABASE
    // =========================
    if (url.pathname === "/api/test-db") {
      try {
        const result = await env.DB
          .prepare(
            "SELECT name FROM sqlite_master WHERE type='table'"
          )
          .all();

        return Response.json({
          success: true,
          database: "tapnivo-db",
          tables: result.results
        });

      } catch (error) {
        return Response.json(
          {
            success: false,
            error: error.message
          },
          { status: 500 }
        );
      }
    }


    // =========================
    // GET ALL CLIENTS
    // =========================
    if (
      url.pathname === "/api/clients" &&
      request.method === "GET"
    ) {
      try {
        const result = await env.DB
          .prepare(
            "SELECT * FROM clients ORDER BY id DESC"
          )
          .all();

        return Response.json({
          success: true,
          clients: result.results
        });

      } catch (error) {
        return Response.json(
          {
            success: false,
            error: error.message
          },
          { status: 500 }
        );
      }
    }


    // =========================
    // CREATE CLIENT
    // =========================
    if (
      url.pathname === "/api/clients" &&
      request.method === "POST"
    ) {
      try {
        const data = await request.json();

        if (!data.name) {
          return Response.json(
            {
              success: false,
              error: "Le nom du client est obligatoire."
            },
            { status: 400 }
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

        return Response.json({
          success: true,
          message: "Client créé avec succès.",
          slug: slug
        });

      } catch (error) {
        return Response.json(
          {
            success: false,
            error: error.message
          },
          { status: 500 }
        );
      }
    }


    // =========================
    // CLIENT PROFILE
    // =========================
    if (url.pathname.startsWith("/client/")) {

      const slug =
        url.pathname
          .replace("/client/", "")
          .replace(/\/$/, "");

      if (!slug) {
        return new Response(
          "Profil introuvable",
          { status: 404 }
        );
      }

      try {

        const result = await env.DB
          .prepare(
            "SELECT * FROM clients WHERE slug = ? LIMIT 1"
          )
          .bind(slug)
          .first();

        if (!result) {
          return new Response(
            "Client introuvable",
            { status: 404 }
          );
        }


        const escapeHTML = (value) => {
          if (!value) return "";

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

* {
  box-sizing: border-box;
}

body {
  margin: 0;
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

  color: #111827;
}

.container {
  max-width: 600px;
  margin: auto;
  padding: 40px 20px;
}

.profile {
  background: white;
  border-radius: 25px;
  padding: 35px 25px;
  text-align: center;
  box-shadow:
    0 15px 40px
    rgba(0,0,0,0.08);
}

.logo {
  font-size: 20px;
  font-weight: 800;
  margin-bottom: 30px;
}

.logo span {
  color: #4f46e5;
}

.avatar {
  width: 100px;
  height: 100px;
  border-radius: 50%;
  margin: auto auto 20px;

  background:
    #eef2ff;

  display: flex;
  align-items: center;
  justify-content: center;

  font-size: 40px;
}

h1 {
  margin: 0;
  font-size: 28px;
}

.profession {
  color: #4f46e5;
  font-weight: bold;
  margin-top: 8px;
}

.bio {
  color: #6b7280;
  line-height: 1.6;
  margin: 20px 0;
}

.buttons {
  display: grid;
  gap: 10px;
  margin-top: 25px;
}

.button {
  display: block;
  padding: 14px;
  border-radius: 12px;

  text-decoration: none;

  font-weight: bold;

  background: #4f46e5;
  color: white;
}

.button.secondary {
  background: #f3f4f6;
  color: #374151;
}

.info {
  margin-top: 25px;
  text-align: left;
}

.info div {
  padding: 12px 0;
  border-bottom: 1px solid #eee;
}

.label {
  font-size: 12px;
  color: #9ca3af;
}

.value {
  margin-top: 4px;
  font-weight: 600;
}

.footer {
  margin-top: 25px;
  color: #9ca3af;
  font-size: 12px;
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
    ? `<div class="profession">
        ${escapeHTML(result.profession)}
      </div>`
    : ""
}

${
  result.bio
    ? `<div class="bio">
        ${escapeHTML(result.bio)}
      </div>`
    : ""
}


<div class="buttons">

${
  result.phone
    ? `<a
        class="button"
        href="tel:${escapeHTML(result.phone)}"
      >
        📞 Appeler
      </a>`
    : ""
}


${
  result.whatsapp
    ? `<a
        class="button"
        href="https://wa.me/${escapeHTML(
          result.whatsapp.replace(/[^0-9]/g, "")
        )}"
        target="_blank"
      >
        💬 WhatsApp
      </a>`
    : ""
}


${
  result.instagram
    ? `<a
        class="button secondary"
        href="${escapeHTML(result.instagram)}"
        target="_blank"
      >
        Instagram
      </a>`
    : ""
}


${
  result.maps
    ? `<a
        class="button secondary"
        href="${escapeHTML(result.maps)}"
        target="_blank"
      >
        📍 Google Maps
      </a>`
    : ""
}

</div>


<div class="info">

${
  result.email
    ? `<div>
        <div class="label">Email</div>
        <div class="value">
          ${escapeHTML(result.email)}
        </div>
      </div>`
    : ""
}


${
  result.address
    ? `<div>
        <div class="label">Adresse</div>
        <div class="value">
          ${escapeHTML(result.address)}
        </div>
      </div>`
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


    // =========================
    // STATIC FILES
    // =========================
    return env.ASSETS.fetch(request);
  }
};
