export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Test de connexion avec D1
    if (url.pathname === "/api/test-db") {
      try {
        const result = await env.DB
          .prepare("SELECT name FROM sqlite_master WHERE type='table'")
          .all();

        return Response.json({
          success: true,
          database: "tapnivo-db",
          tables: result.results
        });

      } catch (error) {
        return Response.json({
          success: false,
          error: error.message
        }, { status: 500 });
      }
    }

    // API: récupérer tous les clients
    if (url.pathname === "/api/clients" && request.method === "GET") {
      try {
        const result = await env.DB
          .prepare("SELECT * FROM clients ORDER BY id DESC")
          .all();

        return Response.json({
          success: true,
          clients: result.results
        });

      } catch (error) {
        return Response.json({
          success: false,
          error: error.message
        }, { status: 500 });
      }
    }

    // API: créer un client
    if (url.pathname === "/api/clients" && request.method === "POST") {
      try {
        const data = await request.json();

        if (!data.name) {
          return Response.json({
            success: false,
            error: "Le nom du client est obligatoire."
          }, { status: 400 });
        }

        const slug = data.slug ||
          data.name
            .toLowerCase()
            .normalize("NFD")
            .replace(/[\u0300-\u036f]/g, "")
            .replace(/[^a-z0-9]+/g, "-")
            .replace(/^-|-$/g, "");

        await env.DB.prepare(`
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
        return Response.json({
          success: false,
          error: error.message
        }, { status: 500 });
      }
    }

    // Pour les autres requêtes:
    // laisser Cloudflare servir les fichiers HTML/CSS/JS
    return env.ASSETS.fetch(request);
  }
};
