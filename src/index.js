// =====================================================
// PART 1 / 4 — CORE + ADMIN + CLIENTS
// =====================================================

export default {
  async fetch(request, env) {

    const url = new URL(request.url);

    // =====================================================
    // HELPERS
    // =====================================================

    const json = (data, status = 200, extraHeaders = {}) =>
      new Response(JSON.stringify(data, null, 2), {
        status,
        headers: {
          "Content-Type": "application/json; charset=UTF-8",
          "Cache-Control": "no-store",
          ...extraHeaders
        }
      });

    const html = (content, status = 200) =>
      new Response(content, {
        status,
        headers: {
          "Content-Type": "text/html; charset=UTF-8"
        }
      });

    const escapeHTML = (value) => {
      if (value === null || value === undefined) return "";

      return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    };

    const getCookie = (request, name) => {
      const cookieHeader = request.headers.get("Cookie");

      if (!cookieHeader) return null;

      for (const cookie of cookieHeader.split(";")) {
        const parts = cookie.trim().split("=");

        if (parts[0] === name) {
          return parts.slice(1).join("=");
        }
      }

      return null;
    };

    const timingSafeEqual = (a, b) => {
      if (a.length !== b.length) return false;

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
      const padding = (4 - (input.length % 4)) % 4;

      const base64 =
        input.replace(/-/g, "+").replace(/_/g, "/") +
        "=".repeat(padding);

      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);

      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }

      return bytes;
    };

    const parseConfig = (value) => {
      if (!value) return null;

      if (typeof value === "object") return value;

      try {
        return JSON.parse(value);
      } catch {
        return value;
      }
    };

    const isValidHttpUrl = (value) => {
      if (!value) return false;

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
    // CONSTANTS
    // =====================================================

    const SERVICE_TYPES = [
      "google_review",
      "instagram",
      "whatsapp",
      "tiktok",
      "digital_card",
      "menu",
      "wifi",
      "custom_link"
    ];

    const SERVICE_STATUSES = [
      "draft",
      "active",
      "inactive"
    ];

    const SUPPORT_TYPES = [
      "nfc_stand",
      "nfc_card",
      "qr_plaque"
    ];

    const SUPPORT_STATUSES = [
      "available",
      "active",
      "inactive"
    ];

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

      if (!token || !env.ADMIN_KEY) return false;

      const parts = token.split(".");

      if (parts.length !== 2) return false;

      try {

        const timestampBytes =
          fromBase64url(parts[0]);

        const timestamp =
          new TextDecoder().decode(timestampBytes);

        const time = Number(timestamp);

        if (!Number.isFinite(time)) return false;

        const now = Date.now();

        if (
          now - time >
          8 * 60 * 60 * 1000
        ) {
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
      const token = getCookie(
        request,
        "tapnivo_admin"
      );

      return await verifyAdminToken(token);
    };

    // =====================================================
    // LOGIN
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

      return json({
        success: true,
        authenticated: await isAdmin()
      });
    }

    // =====================================================
    // LOGOUT
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
      url.pathname === "/api/test-db" &&
      request.method === "GET"
    ) {

      try {

        const result =
          await env.DB
            .prepare(`
              SELECT name
              FROM sqlite_master
              WHERE type = 'table'
              ORDER BY name
            `)
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
    // CLIENTS GET
    // =====================================================

    if (
      url.pathname === "/api/clients" &&
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
              SELECT *
              FROM clients
              ORDER BY id DESC
            `)
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
    // CLIENTS POST
    // =====================================================

    if (
      url.pathname === "/api/clients" &&
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

        const name =
          String(data.name || "").trim();

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
            .replace(/[\u0300-\u036f]/g, "")
            .replace(/[^a-z0-9]+/g, "-")
            .replace(/^-|-$/g, "");

        if (!baseSlug) {
          baseSlug = "client";
        }

        const slug =
          data.slug ||
          `${baseSlug}-${Date.now()}`;

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
            error: error.message
          },
          500
        );
      }
    }

    // =====================================================
    // CLIENT ID
    // =====================================================

    const clientIdMatch =
      url.pathname.match(
        /^\/api\/clients\/(\d+)$/
      );

    const clientId =
      clientIdMatch
        ? Number(clientIdMatch[1])
        : null;

    // =====================================================
    // CLIENT UPDATE
    // =====================================================

    if (
      clientId !== null &&
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
              FROM clients
              WHERE id = ?
              LIMIT 1
            `)
            .bind(clientId)
            .first();

        if (!existing) {
          return json(
            {
              success: false,
              error: "Client introuvable."
            },
            404
          );
        }

        const data =
          await request.json();

        const fields = [
          "name",
          "profession",
          "bio",
          "phone",
          "whatsapp",
          "email",
          "instagram",
          "facebook",
          "tiktok",
          "linkedin",
          "address",
          "maps",
          "website",
          "reviews",
          "photo_url",
          "slug"
        ];

        const updates = [];
        const values = [];

        for (const field of fields) {

          if (
            Object.prototype.hasOwnProperty.call(
              data,
              field
            )
          ) {

            let value = data[field];

            if (typeof value === "string") {
              value = value.trim();
            }

            if (
              field === "name" &&
              !value
            ) {
              return json(
                {
                  success: false,
                  error:
                    "Le nom du client est obligatoire."
                },
                400
              );
            }

            updates.push(`${field} = ?`);
            values.push(value || null);
          }
        }

        if (!updates.length) {
          return json({
            success: true,
            message: "Aucune modification."
          });
        }

        updates.push(
          "updated_at = CURRENT_TIMESTAMP"
        );

        values.push(clientId);

        await env.DB
          .prepare(`
            UPDATE clients
            SET ${updates.join(", ")}
            WHERE id = ?
          `)
          .bind(...values)
          .run();

        return json({
          success: true,
          message:
            "Client modifié avec succès."
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
    // CLIENT DELETE
    // =====================================================

    if (
      clientId !== null &&
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

        const existing =
          await env.DB
            .prepare(`
              SELECT id
              FROM clients
              WHERE id = ?
              LIMIT 1
            `)
            .bind(clientId)
            .first();

        if (!existing) {
          return json(
            {
              success: false,
              error: "Client introuvable."
            },
            404
          );
        }

        await env.DB
          .prepare(`
            DELETE FROM clients
            WHERE id = ?
          `)
          .bind(clientId)
          .run();

        return json({
          success: true,
          message:
            "Client supprimé avec succès."
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
    // SERVICE CODE HELPERS
    // =====================================================

    const generateServiceCode = () => {

      const chars =
        "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

      const bytes =
        new Uint8Array(8);

      crypto.getRandomValues(bytes);

      let code = "";

      for (let i = 0; i < bytes.length; i++) {
        code +=
          chars[
            bytes[i] % chars.length
          ];
      }

      return code;
    };

    const generateUniqueServiceCode =
      async () => {

        for (let attempt = 0; attempt < 30; attempt++) {

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
    // SUPPORT CODE HELPERS
    // =====================================================

    const SUPPORT_CHARS =
      "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    const generateSupportCode = (
      supportType
    ) => {

      const bytes =
        new Uint8Array(8);

      crypto.getRandomValues(bytes);

      let prefix = "SUP";

      if (supportType === "nfc_stand") {
        prefix = "ST";
      } else if (supportType === "nfc_card") {
        prefix = "CARD";
      } else if (
        supportType === "qr_plaque" ||
        supportType === "qr"
      ) {
        prefix = "QR";
      }

      let code = "";

      for (let i = 0; i < bytes.length; i++) {
        code +=
          SUPPORT_CHARS[
            bytes[i] % SUPPORT_CHARS.length
          ];
      }

      return `${prefix}-${code}`;
    };

    const generateUniqueSupportCode =
      async (supportType) => {

        for (let attempt = 0; attempt < 30; attempt++) {

          const code =
            generateSupportCode(
              supportType
            );

          const existing =
            await env.DB
              .prepare(`
                SELECT id
                FROM supports
                WHERE support_code = ?
                LIMIT 1
              `)
              .bind(code)
              .first();

          if (!existing) {
            return code;
          }
        }

        throw new Error(
          "Impossible de générer un code Support unique."
        );
      };

    // =====================================================
    // END PART 1
    // =====================================================
  // =====================================================
// PART 2 / 4 — SERVICE TYPES + SERVICES
// =====================================================

// =====================================================
// GET SERVICE TYPES
// =====================================================

    if (
      url.pathname === "/api/service-types" &&
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
                code,
                name,
                icon,
                description,
                active,
                created_at
              FROM service_types
              ORDER BY id ASC
            `)
            .all();

        return json({
          success: true,
          service_types: result.results
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
// ADD SERVICE TYPE
// =====================================================

    if (
      url.pathname === "/api/service-types" &&
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

        const code =
          String(data.code || "")
            .trim()
            .toLowerCase();

        const name =
          String(data.name || "").trim();

        const icon =
          data.icon
            ? String(data.icon).trim()
            : null;

        const description =
          data.description
            ? String(data.description).trim()
            : null;

        if (!code) {
          return json(
            {
              success: false,
              error:
                "Code du service obligatoire."
            },
            400
          );
        }

        if (!/^[a-z0-9_]+$/.test(code)) {
          return json(
            {
              success: false,
              error:
                "Le code doit contenir uniquement lettres, chiffres et underscore."
            },
            400
          );
        }

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

        const exists =
          await env.DB
            .prepare(`
              SELECT id
              FROM service_types
              WHERE code = ?
              LIMIT 1
            `)
            .bind(code)
            .first();

        if (exists) {
          return json(
            {
              success: false,
              error:
                "Ce type de service existe déjà."
            },
            409
          );
        }

        await env.DB
          .prepare(`
            INSERT INTO service_types (
              code,
              name,
              icon,
              description,
              active
            )
            VALUES (?, ?, ?, ?, 1)
          `)
          .bind(
            code,
            name,
            icon,
            description
          )
          .run();

        return json({
          success: true,
          message:
            "Type de service créé avec succès.",
          code
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
// SERVICE TYPE ID
// =====================================================

    const serviceTypeIdMatch =
      url.pathname.match(
        /^\/api\/service-types\/(\d+)$/
      );

    const serviceTypeId =
      serviceTypeIdMatch
        ? Number(serviceTypeIdMatch[1])
        : null;

// =====================================================
// UPDATE SERVICE TYPE
// =====================================================

    if (
      serviceTypeId !== null &&
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
              FROM service_types
              WHERE id = ?
              LIMIT 1
            `)
            .bind(serviceTypeId)
            .first();

        if (!existing) {
          return json(
            {
              success: false,
              error:
                "Type de service introuvable."
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
            "name"
          )
        ) {

          const value =
            String(data.name || "").trim();

          if (!value) {
            return json(
              {
                success: false,
                error: "Nom obligatoire."
              },
              400
            );
          }

          updates.push("name = ?");
          values.push(value);
        }

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "icon"
          )
        ) {

          updates.push("icon = ?");
          values.push(
            data.icon
              ? String(data.icon).trim()
              : null
          );
        }

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "description"
          )
        ) {

          updates.push("description = ?");
          values.push(
            data.description
              ? String(data.description).trim()
              : null
          );
        }

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "active"
          )
        ) {

          updates.push("active = ?");
          values.push(
            data.active ? 1 : 0
          );
        }

        if (!updates.length) {
          return json({
            success: true,
            message: "Aucune modification."
          });
        }

        values.push(serviceTypeId);

        await env.DB
          .prepare(`
            UPDATE service_types
            SET ${updates.join(", ")}
            WHERE id = ?
          `)
          .bind(...values)
          .run();

        return json({
          success: true,
          message:
            "Type de service modifié avec succès."
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
                s.status,
                s.service_code,
                s.destination_url,
                s.config,
                s.created_at,
                s.activated_at,
                s.updated_at,

                c.name AS client_name,
                c.profession AS client_profession,
                c.photo_url AS client_photo_url,

                st.name AS service_type_name,
                st.icon AS service_type_icon,

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
                ) AS last_scan,

                (
                  SELECT COUNT(*)
                  FROM supports sp
                  WHERE sp.service_id = s.id
                ) AS supports_count

              FROM services s

              LEFT JOIN clients c
                ON s.client_id = c.id

              LEFT JOIN service_types st
                ON s.service_type = st.code

              ORDER BY s.id DESC
            `)
            .all();

        const services =
          result.results.map(service => ({
            ...service,

            scans_count:
              Number(service.scans_count || 0),

            scans_today:
              Number(service.scans_today || 0),

            scans_7_days:
              Number(service.scans_7_days || 0),

            scans_30_days:
              Number(service.scans_30_days || 0),

            supports_count:
              Number(service.supports_count || 0),

            config:
              parseConfig(service.config),

            qr_url:
              `${url.origin}/s/${encodeURIComponent(
                service.service_code
              )}`,

            nfc_url:
              `${url.origin}/s/${encodeURIComponent(
                service.service_code
              )}`
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
          String(data.service_type || "")
            .trim();

        const serviceName =
          String(data.service_name || "")
            .trim();

        const destinationUrl =
          String(data.destination_url || "")
            .trim();

        const status =
          String(data.status || "draft")
            .trim();

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

        const serviceTypeExists =
          await env.DB
            .prepare(`
              SELECT id, code, name
              FROM service_types
              WHERE code = ?
              AND active = 1
              LIMIT 1
            `)
            .bind(serviceType)
            .first();

        if (!serviceTypeExists) {
          return json(
            {
              success: false,
              error:
                "Ce type de service n'existe pas ou est désactivé."
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

        if (!SERVICE_STATUSES.includes(status)) {
          return json(
            {
              success: false,
              error: "Statut invalide."
            },
            400
          );
        }

        if (
          destinationUrl &&
          !isValidHttpUrl(destinationUrl)
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

        let config = null;

        if (
          data.config !== undefined &&
          data.config !== null
        ) {

          if (
            typeof data.config === "string"
          ) {

            try {
              JSON.parse(data.config);
              config = data.config;
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
                JSON.stringify(data.config);
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

        const serviceCode =
          await generateUniqueServiceCode();

        await env.DB
          .prepare(`
            INSERT INTO services (
              client_id,
              service_type,
              service_name,
              status,
              service_code,
              destination_url,
              config,
              activated_at,
              updated_at
            )
            VALUES (
              ?, ?, ?, ?, ?,
              ?, ?,
              ${status === "active"
                ? "CURRENT_TIMESTAMP"
                : "NULL"},
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
            config
          )
          .run();

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

        const supports =
          await env.DB
            .prepare(`
              SELECT
                id,
                support_code,
                support_type,
                status,
                created_at,
                activated_at
              FROM supports
              WHERE service_id = ?
              ORDER BY id DESC
            `)
            .bind(serviceId)
            .all();

        return json({
          success: true,
          service,

          statistics: {
            total:
              Number(statistics?.total || 0),

            today:
              Number(statistics?.today || 0),

            seven_days:
              Number(statistics?.seven_days || 0),

            thirty_days:
              Number(statistics?.thirty_days || 0),

            last_scan:
              statistics?.last_scan || null
          },

          supports:
            supports.results
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

          const value =
            Number(data.client_id);

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

          updates.push("client_id = ?");
          values.push(value);
        }

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "service_type"
          )
        ) {

          const value =
            String(data.service_type || "")
              .trim();

          const type =
            await env.DB
              .prepare(`
                SELECT id
                FROM service_types
                WHERE code = ?
                AND active = 1
                LIMIT 1
              `)
              .bind(value)
              .first();

          if (!type) {
            return json(
              {
                success: false,
                error:
                  "Type de service invalide."
              },
              400
            );
          }

          updates.push("service_type = ?");
          values.push(value);
        }

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "service_name"
          )
        ) {

          const value =
            String(data.service_name || "")
              .trim();

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

          updates.push("service_name = ?");
          values.push(value);
        }

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "destination_url"
          )
        ) {

          const value =
            String(data.destination_url || "")
              .trim();

          if (
            value &&
            !isValidHttpUrl(value)
          ) {
            return json(
              {
                success: false,
                error: "URL invalide."
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

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "config"
          )
        ) {

          let value = null;

          if (data.config !== null) {

            if (
              typeof data.config === "string"
            ) {

              try {
                JSON.parse(data.config);
                value = data.config;
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
                value =
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

          updates.push("config = ?");
          values.push(value);
        }

        if (
          Object.prototype.hasOwnProperty.call(
            data,
            "status"
          )
        ) {

          const value =
            String(data.status || "")
              .trim();

          if (
            !SERVICE_STATUSES.includes(value)
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

          updates.push("status = ?");
          values.push(value);

          if (value === "active") {

            updates.push(
              "activated_at = COALESCE(activated_at, CURRENT_TIMESTAMP)"
            );

          } else {

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

        await env.DB
          .prepare(`
            UPDATE supports
            SET
              service_id = NULL,
              status = 'available',
              activated_at = NULL
            WHERE service_id = ?
          `)
          .bind(serviceId)
          .run();

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
// END PART 2
// =====================================================
  // =====================================================
// PART 3 / 4 — SUPPORTS
// =====================================================

// =====================================================
// SUPPORT PUBLIC URL
// =====================================================

    const supportPublicUrl = (
      supportCode
    ) => {
      return (
        `${url.origin}/r/${encodeURIComponent(
          supportCode
        )}`
      );
    };

// =====================================================
// GET SUPPORTS
// =====================================================

    if (
      url.pathname === "/api/supports" &&
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

                sp.id,
                sp.support_code,
                sp.support_type,
                sp.service_id,
                sp.status,
                sp.created_at,
                sp.activated_at,

                s.service_name,
                s.service_type,
                s.service_code,
                s.status AS service_status,

                c.id AS client_id,
                c.name AS client_name,

                (
                  SELECT COUNT(*)
                  FROM support_scans ss
                  WHERE ss.support_id = sp.id
                ) AS scans_count,

                (
                  SELECT MAX(ss.scanned_at)
                  FROM support_scans ss
                  WHERE ss.support_id = sp.id
                ) AS last_scan

              FROM supports sp

              LEFT JOIN services s
                ON sp.service_id = s.id

              LEFT JOIN clients c
                ON s.client_id = c.id

              ORDER BY sp.id ASC
            `)
            .all();

        const supports =
          result.results.map(support => ({
            ...support,

            scans_count:
              Number(
                support.scans_count || 0
              ),

            support_url:
              supportPublicUrl(
                support.support_code
              ),

            qr_url:
              supportPublicUrl(
                support.support_code
              ),

            nfc_url:
              supportPublicUrl(
                support.support_code
              )
          }));

        return json({
          success: true,
          total: supports.length,
          supports
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
// GET AVAILABLE SUPPORTS
// =====================================================

    if (
      url.pathname ===
        "/api/supports/available" &&
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

        const requestedType =
          url.searchParams.get("type");

        let query = `
          SELECT
            id,
            support_code,
            support_type,
            service_id,
            status,
            created_at,
            activated_at
          FROM supports
          WHERE status = 'available'
        `;

        const bindings = [];

        if (requestedType) {
          query += `
            AND support_type = ?
          `;

          bindings.push(requestedType);
        }

        query += `
          ORDER BY id ASC
        `;

        const result =
          await env.DB
            .prepare(query)
            .bind(...bindings)
            .all();

        const supports =
          result.results.map(support => ({
            ...support,

            support_url:
              supportPublicUrl(
                support.support_code
              ),

            qr_url:
              supportPublicUrl(
                support.support_code
              ),

            nfc_url:
              supportPublicUrl(
                support.support_code
              )
          }));

        return json({
          success: true,
          total: supports.length,
          supports
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
// CREATE SUPPORT
// =====================================================

    if (
      url.pathname === "/api/supports" &&
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

        const supportType =
          String(data.support_type || "")
            .trim()
            .toLowerCase();

        const allowedSupportTypes = [
          "nfc_stand",
          "nfc_card",
          "qr_plaque"
        ];

        if (
          !allowedSupportTypes.includes(
            supportType
          )
        ) {
          return json(
            {
              success: false,
              error:
                "Type de Support invalide. Utilisez nfc_stand, nfc_card ou qr_plaque."
            },
            400
          );
        }

        const supportCode =
          await generateUniqueSupportCode(
            supportType
          );

        await env.DB
          .prepare(`
            INSERT INTO supports (
              support_code,
              support_type,
              service_id,
              status
            )
            VALUES (
              ?,
              ?,
              NULL,
              'available'
            )
          `)
          .bind(
            supportCode,
            supportType
          )
          .run();

        const supportUrl =
          supportPublicUrl(
            supportCode
          );

        return json({
          success: true,

          message:
            "Support créé avec succès.",

          support: {
            support_code:
              supportCode,

            support_type:
              supportType,

            status:
              "available",

            support_url:
              supportUrl,

            qr_url:
              supportUrl,

            nfc_url:
              supportUrl
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
// BULK CREATE SUPPORTS
// =====================================================

    if (
      url.pathname === "/api/supports/bulk" &&
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

        const supportTypes = [
          "nfc_stand",
          "nfc_card",
          "qr_plaque"
        ];

        const counts = {};
        let totalRequested = 0;

        for (const type of supportTypes) {

          const count =
            Number(data[type] || 0);

          if (
            !Number.isInteger(count) ||
            count < 0
          ) {
            return json(
              {
                success: false,
                error:
                  `La quantité pour ${type} doit être un nombre entier positif.`
              },
              400
            );
          }

          counts[type] = count;
          totalRequested += count;
        }

        if (totalRequested <= 0) {
          return json(
            {
              success: false,
              error:
                "Indiquez au moins un Support à créer."
            },
            400
          );
        }

        if (totalRequested > 5000) {
          return json(
            {
              success: false,
              error:
                "Maximum 5000 Supports par opération."
            },
            400
          );
        }

        const created = [];

        for (const type of supportTypes) {

          const count = counts[type];

          for (let i = 0; i < count; i++) {

            const supportCode =
              await generateUniqueSupportCode(
                type
              );

            await env.DB
              .prepare(`
                INSERT INTO supports (
                  support_code,
                  support_type,
                  service_id,
                  status
                )
                VALUES (
                  ?,
                  ?,
                  NULL,
                  'available'
                )
              `)
              .bind(
                supportCode,
                type
              )
              .run();

            const supportUrl =
              supportPublicUrl(
                supportCode
              );

            created.push({
              support_code:
                supportCode,

              support_type:
                type,

              status:
                "available",

              support_url:
                supportUrl,

              qr_url:
                supportUrl,

              nfc_url:
                supportUrl
            });
          }
        }

        return json({
          success: true,

          message:
            `${created.length} Support(s) créé(s) avec succès.`,

          total:
            created.length,

          counts,

          supports:
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
// SUPPORT ID
// =====================================================

    const supportIdMatch =
      url.pathname.match(
        /^\/api\/supports\/(\d+)$/
      );

    const supportId =
      supportIdMatch
        ? Number(supportIdMatch[1])
        : null;

// =====================================================
// GET SUPPORT DETAILS
// =====================================================

    if (
      supportId !== null &&
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

        const support =
          await env.DB
            .prepare(`
              SELECT

                sp.id,
                sp.support_code,
                sp.support_type,
                sp.service_id,
                sp.status,
                sp.created_at,
                sp.activated_at,

                s.service_name,
                s.service_type,
                s.service_code,
                s.status AS service_status,

                c.id AS client_id,
                c.name AS client_name

              FROM supports sp

              LEFT JOIN services s
                ON sp.service_id = s.id

              LEFT JOIN clients c
                ON s.client_id = c.id

              WHERE sp.id = ?

              LIMIT 1
            `)
            .bind(supportId)
            .first();

        if (!support) {
          return json(
            {
              success: false,
              error:
                "Support introuvable."
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

              FROM support_scans

              WHERE support_id = ?
            `)
            .bind(supportId)
            .first();

        return json({
          success: true,

          support: {
            ...support,

            support_url:
              supportPublicUrl(
                support.support_code
              ),

            qr_url:
              supportPublicUrl(
                support.support_code
              ),

            nfc_url:
              supportPublicUrl(
                support.support_code
              )
          },

          statistics: {
            total:
              Number(statistics?.total || 0),

            today:
              Number(statistics?.today || 0),

            seven_days:
              Number(statistics?.seven_days || 0),

            thirty_days:
              Number(statistics?.thirty_days || 0),

            last_scan:
              statistics?.last_scan || null
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
// ASSIGN SUPPORT
// =====================================================

    if (
      supportId !== null &&
      url.pathname ===
        `/api/supports/${supportId}/assign` &&
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

        const serviceId =
          Number(data.service_id);

        if (!serviceId) {
          return json(
            {
              success: false,
              error:
                "service_id est obligatoire."
            },
            400
          );
        }

        const support =
          await env.DB
            .prepare(`
              SELECT *
              FROM supports
              WHERE id = ?
              LIMIT 1
            `)
            .bind(supportId)
            .first();

        if (!support) {
          return json(
            {
              success: false,
              error:
                "Support introuvable."
            },
            404
          );
        }

        if (
          support.status === "active" &&
          support.service_id !== null
        ) {
          return json(
            {
              success: false,
              error:
                "Ce Support est déjà associé à un Service."
            },
            409
          );
        }

        const service =
          await env.DB
            .prepare(`
              SELECT
                id,
                client_id,
                service_name,
                service_type,
                service_code,
                status
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

        if (service.status !== "active") {
          return json(
            {
              success: false,
              error:
                "Le Service doit être actif avant de l'associer à un Support."
            },
            409
          );
        }

        await env.DB
          .prepare(`
            UPDATE supports
            SET
              service_id = ?,
              status = 'active',
              activated_at =
                COALESCE(
                  activated_at,
                  CURRENT_TIMESTAMP
                )
            WHERE id = ?
          `)
          .bind(
            serviceId,
            supportId
          )
          .run();

        return json({
          success: true,

          message:
            "Support associé au Service avec succès.",

          support: {
            id:
              supportId,

            support_code:
              support.support_code,

            support_type:
              support.support_type,

            service_id:
              service.id,

            service_code:
              service.service_code,

            support_url:
              supportPublicUrl(
                support.support_code
              )
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
// RESET SUPPORT
// =====================================================

    if (
      supportId !== null &&
      url.pathname ===
        `/api/supports/${supportId}/reset` &&
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

        const support =
          await env.DB
            .prepare(`
              SELECT *
              FROM supports
              WHERE id = ?
              LIMIT 1
            `)
            .bind(supportId)
            .first();

        if (!support) {
          return json(
            {
              success: false,
              error:
                "Support introuvable."
            },
            404
          );
        }

        await env.DB
          .prepare(`
            UPDATE supports
            SET
              service_id = NULL,
              status = 'available',
              activated_at = NULL
            WHERE id = ?
          `)
          .bind(supportId)
          .run();

        return json({
          success: true,

          message:
            "Support réinitialisé avec succès.",

          support_code:
            support.support_code,

          status:
            "available",

          support_url:
            supportPublicUrl(
              support.support_code
            )
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
// CHANGE SUPPORT STATUS
// =====================================================

    if (
      supportId !== null &&
      url.pathname ===
        `/api/supports/${supportId}/status` &&
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

        const data =
          await request.json();

        const status =
          String(data.status || "").trim();

        if (
          !SUPPORT_STATUSES.includes(status)
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

        const support =
          await env.DB
            .prepare(`
              SELECT *
              FROM supports
              WHERE id = ?
              LIMIT 1
            `)
            .bind(supportId)
            .first();

        if (!support) {
          return json(
            {
              success: false,
              error:
                "Support introuvable."
            },
            404
          );
        }

        if (
          status === "available" &&
          support.service_id !== null
        ) {
          return json(
            {
              success: false,
              error:
                "Impossible de mettre un Support associé en available. Utilisez reset."
            },
            409
          );
        }

        await env.DB
          .prepare(`
            UPDATE supports
            SET status = ?
            WHERE id = ?
          `)
          .bind(
            status,
            supportId
          )
          .run();

        return json({
          success: true,

          message:
            "Statut du Support modifié.",

          status
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
// DELETE SUPPORT
// =====================================================

    if (
      supportId !== null &&
      request.method === "DELETE" &&
      url.pathname ===
        `/api/supports/${supportId}`
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

        const support =
          await env.DB
            .prepare(`
              SELECT *
              FROM supports
              WHERE id = ?
              LIMIT 1
            `)
            .bind(supportId)
            .first();

        if (!support) {
          return json(
            {
              success: false,
              error:
                "Support introuvable."
            },
            404
          );
        }

        if (
          support.service_id !== null ||
          support.status === "active"
        ) {
          return json(
            {
              success: false,
              error:
                "Impossible de supprimer un Support actif ou associé à un Service. Faites Reset d'abord."
            },
            409
          );
        }

        await env.DB
          .prepare(`
            DELETE FROM supports
            WHERE id = ?
          `)
          .bind(supportId)
          .run();

        return json({
          success: true,
          message:
            "Support supprimé avec succès."
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
// END PART 3
// =====================================================
  // =====================================================
// PART 4 / 4 — PUBLIC ROUTES + STATIC
// =====================================================

// =====================================================
// PUBLIC SUPPORT ROUTE
// /r/SUPPORTCODE
// =====================================================

    if (
      url.pathname.startsWith("/r/")
    ) {

      const supportCode =
        url.pathname
          .replace("/r/", "")
          .replace(/\/$/, "")
          .trim();

      if (!supportCode) {
        return html(
          "Support introuvable",
          404
        );
      }

      try {

        const support =
          await env.DB
            .prepare(`
              SELECT

                sp.id,
                sp.support_code,
                sp.support_type,
                sp.service_id,
                sp.status,

                s.service_code,
                s.service_type,
                s.service_name,
                s.destination_url,
                s.status AS service_status,
                s.config,

                c.id AS client_id,
                c.name AS client_name

              FROM supports sp

              LEFT JOIN services s
                ON sp.service_id = s.id

              LEFT JOIN clients c
                ON s.client_id = c.id

              WHERE sp.support_code = ?

              LIMIT 1
            `)
            .bind(supportCode)
            .first();

        if (!support) {
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
font-family:Arial,Helvetica,sans-serif;
background:#f5f7fb;
text-align:center;
padding:20px;
}
.box{
background:white;
max-width:430px;
width:100%;
padding:35px 25px;
border-radius:24px;
box-shadow:0 18px 45px rgba(0,0,0,.08);
}
.logo{
font-size:24px;
font-weight:800;
margin-bottom:25px;
}
.logo span{color:#4f46e5;}
.icon{font-size:55px;margin-bottom:15px;}
p{color:#6b7280;line-height:1.6;}
</style>
</head>
<body>
<div class="box">
<div class="logo">TAP<span>NIVO</span></div>
<div class="icon">📲</div>
<h2>Support introuvable</h2>
<p>Ce QR Code ou NFC n'est pas reconnu.</p>
</div>
</body>
</html>
`,
            404
          );
        }

        if (
          support.status !== "active" ||
          !support.service_id ||
          support.service_status !== "active"
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
*{box-sizing:border-box;}
body{
margin:0;
min-height:100vh;
display:flex;
align-items:center;
justify-content:center;
font-family:Arial,Helvetica,sans-serif;
background:linear-gradient(135deg,#f5f7fb,#eef2ff);
padding:20px;
text-align:center;
}
.box{
width:100%;
max-width:430px;
background:white;
padding:35px 25px;
border-radius:25px;
box-shadow:0 18px 45px rgba(0,0,0,.08);
}
.logo{
font-size:24px;
font-weight:800;
margin-bottom:25px;
}
.logo span{color:#4f46e5;}
.icon{font-size:55px;margin-bottom:15px;}
h2{margin:0 0 10px;}
p{color:#6b7280;line-height:1.6;}
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
<div class="logo">TAP<span>NIVO</span></div>
<div class="icon">📲</div>
<h2>Support indisponible</h2>
<p>Ce support n'est pas actuellement activé.</p>
<div class="code">${escapeHTML(support.support_code)}</div>
</div>
</body>
</html>
`
          );
        }

        await env.DB
          .prepare(`
            INSERT INTO support_scans (
              support_id
            )
            VALUES (?)
          `)
          .bind(support.id)
          .run();

        const serviceCode =
          support.service_code;

        const serviceType =
          support.service_type;

        const destinationUrl =
          support.destination_url;

        const config =
          parseConfig(support.config);

        // =================================================
        // DIGITAL CARD
        // =================================================

        if (
          serviceType === "digital_card"
        ) {

          return Response.redirect(
            `${url.origin}/s/${encodeURIComponent(
              serviceCode
            )}`,
            302
          );
        }

        // =================================================
        // WIFI
        // =================================================

        if (
          serviceType === "wifi"
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
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHTML(support.service_name)}</title>
<style>
*{box-sizing:border-box;}
body{
margin:0;
min-height:100vh;
display:flex;
align-items:center;
justify-content:center;
font-family:Arial,Helvetica,sans-serif;
background:linear-gradient(135deg,#f5f7fb,#eef2ff);
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
.logo span{color:#4f46e5;}
.icon{font-size:50px;margin-bottom:10px;}
h1{font-size:25px;margin:0;}
.client{color:#6b7280;margin-top:8px;}
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
.row:last-child{border-bottom:0;}
.label{font-size:11px;color:#9ca3af;}
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
<div class="logo">TAP<span>NIVO</span></div>
<div class="icon">📶</div>
<h1>${escapeHTML(support.service_name)}</h1>
<div class="client">${escapeHTML(support.client_name || "")}</div>
<div class="wifi">
<div class="row">
<div class="label">NOM DU WI-FI</div>
<div class="value">${escapeHTML(ssid || "—")}</div>
</div>
<div class="row">
<div class="label">MOT DE PASSE</div>
<div class="password">${escapeHTML(password || "—")}</div>
</div>
<div class="row">
<div class="label">SÉCURITÉ</div>
<div class="value">${escapeHTML(security)}</div>
</div>
</div>
<div class="footer">Service Wi-Fi créé avec TAPNIVO</div>
</div>
</body>
</html>
`);
        }

        // =================================================
        // REDIRECT SERVICES
        // =================================================

        if (
          [
            "google_review",
            "instagram",
            "whatsapp",
            "tiktok",
            "menu",
            "custom_link"
          ].includes(serviceType)
        ) {

          if (destinationUrl) {
            return Response.redirect(
              destinationUrl,
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
<body style="font-family:Arial;text-align:center;padding:50px;">
<h2>TAPNIVO</h2>
<p>Aucune destination configurée.</p>
</body>
</html>
`
          );
        }

        if (destinationUrl) {
          return Response.redirect(
            destinationUrl,
            302
          );
        }

        return html(
          `
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>TAPNIVO</title>
</head>
<body style="font-family:Arial;text-align:center;padding:50px;">
<h2>TAPNIVO</h2>
<p>Ce service n'a pas encore été configuré.</p>
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
<body style="font-family:Arial;text-align:center;padding:50px;">
<h2>Erreur serveur</h2>
<p>${escapeHTML(error.message)}</p>
</body>
</html>
`,
          500
        );
      }
    }

// =====================================================
// PUBLIC SERVICE ROUTE
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
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TAPNIVO</title>
</head>
<body style="font-family:Arial;text-align:center;padding:50px;">
<h2>TAPNIVO</h2>
<h3>Service introuvable</h3>
<p>Ce service n'existe pas.</p>
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
.logo span{color:#4f46e5;}
p{
color:#6b7280;
line-height:1.6;
}
</style>
</head>
<body>
<div class="box">
<div class="logo">TAP<span>NIVO</span></div>
<h2>Service indisponible</h2>
<p>Ce service n'est pas actuellement disponible.</p>
</div>
</body>
</html>
`
          );
        }

        await env.DB
          .prepare(`
            INSERT INTO service_scans (
              service_id
            )
            VALUES (?)
          `)
          .bind(service.id)
          .run();

        const config =
          parseConfig(service.config);

        // =================================================
        // WIFI
        // =================================================

        if (
          service.service_type === "wifi"
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
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHTML(service.service_name)}</title>
<style>
*{box-sizing:border-box;}
body{
margin:0;
min-height:100vh;
display:flex;
align-items:center;
justify-content:center;
font-family:Arial,Helvetica,sans-serif;
background:linear-gradient(135deg,#f5f7fb,#eef2ff);
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
.logo span{color:#4f46e5;}
.icon{font-size:50px;margin-bottom:10px;}
h1{font-size:25px;margin:0;}
.client{color:#6b7280;margin-top:8px;}
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
.row:last-child{border-bottom:0;}
.label{font-size:11px;color:#9ca3af;}
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
<div class="logo">TAP<span>NIVO</span></div>
<div class="icon">📶</div>
<h1>${escapeHTML(service.service_name)}</h1>
<div class="client">${escapeHTML(service.client_name || "")}</div>
<div class="wifi">
<div class="row">
<div class="label">NOM DU WI-FI</div>
<div class="value">${escapeHTML(ssid || "—")}</div>
</div>
<div class="row">
<div class="label">MOT DE PASSE</div>
<div class="password">${escapeHTML(password || "—")}</div>
</div>
<div class="row">
<div class="label">SÉCURITÉ</div>
<div class="value">${escapeHTML(security)}</div>
</div>
</div>
<div class="footer">Service Wi-Fi créé avec TAPNIVO</div>
</div>
</body>
</html>
`);
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
              "Client introuvable",
              404
            );
          }

          const whatsappNumber =
            String(
              client.whatsapp || ""
            ).replace(
              /[^0-9]/g,
              ""
            );

          const contactUrl =
            `${url.origin}/contact/${encodeURIComponent(
              service.service_code
            )}.vcf`;

          const buttons = [];

          if (client.phone) {
            buttons.push(`
<a class="button" href="tel:${escapeHTML(client.phone)}">
📞 Appeler
</a>
`);
          }

          if (whatsappNumber) {
            buttons.push(`
<a class="button"
href="https://wa.me/${escapeHTML(whatsappNumber)}"
target="_blank"
rel="noopener">
💬 WhatsApp
</a>
`);
          }

          buttons.push(`
<a class="button contact"
href="${escapeHTML(contactUrl)}">
👤 Ajouter aux contacts
</a>
`);

          if (client.email) {
            buttons.push(`
<a class="button secondary"
href="mailto:${escapeHTML(client.email)}">
✉️ Email
</a>
`);
          }

          if (client.instagram) {
            buttons.push(`
<a class="button secondary"
href="${escapeHTML(client.instagram)}"
target="_blank"
rel="noopener">
📸 Instagram
</a>
`);
          }

          if (client.facebook) {
            buttons.push(`
<a class="button secondary"
href="${escapeHTML(client.facebook)}"
target="_blank"
rel="noopener">
📘 Facebook
</a>
`);
          }

          if (client.tiktok) {
            buttons.push(`
<a class="button secondary"
href="${escapeHTML(client.tiktok)}"
target="_blank"
rel="noopener">
🎵 TikTok
</a>
`);
          }

          if (client.linkedin) {
            buttons.push(`
<a class="button secondary"
href="${escapeHTML(client.linkedin)}"
target="_blank"
rel="noopener">
💼 LinkedIn
</a>
`);
          }

          if (client.maps) {
            buttons.push(`
<a class="button secondary"
href="${escapeHTML(client.maps)}"
target="_blank"
rel="noopener">
📍 Google Maps
</a>
`);
          }

          if (client.website) {
            buttons.push(`
<a class="button secondary"
href="${escapeHTML(client.website)}"
target="_blank"
rel="noopener">
🌐 Site web
</a>
`);
          }

          if (client.reviews) {
            buttons.push(`
<a class="button secondary"
href="${escapeHTML(client.reviews)}"
target="_blank"
rel="noopener">
⭐ Google Reviews
</a>
`);
          }

          const photoHTML =
            client.photo_url
              ? `
<img
class="profile-photo"
src="${escapeHTML(client.photo_url)}"
alt="${escapeHTML(client.name)}"
loading="lazy">
`
              : `
<div class="avatar">👤</div>
`;

          return html(`
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#4f46e5">
<title>${escapeHTML(client.name)} | TAPNIVO</title>
<style>
*{box-sizing:border-box;}
body{
margin:0;
font-family:Arial,Helvetica,sans-serif;
background:linear-gradient(135deg,#f5f7fb,#eef2ff);
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
box-shadow:0 18px 50px rgba(0,0,0,.09);
}
.logo{
font-size:21px;
font-weight:800;
margin-bottom:25px;
}
.logo span{color:#4f46e5;}
.profile-photo{
width:115px;
height:115px;
border-radius:50%;
object-fit:cover;
display:block;
margin:0 auto 18px;
border:4px solid #eef2ff;
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
.button.contact{background:#111827;}
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
border-bottom:1px solid #eeeeee;
}
.info-row:last-child{border-bottom:0;}
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
<div class="logo">TAP<span>NIVO</span></div>

${photoHTML}

<h1>${escapeHTML(client.name)}</h1>

${
  client.profession
    ? `
<div class="profession">
${escapeHTML(client.profession)}
</div>
`
    : ""
}

${
  client.bio
    ? `
<div class="bio">
${escapeHTML(client.bio)}
</div>
`
    : ""
}

<div class="buttons">
${buttons.join("")}
</div>

<div class="info">

${
  client.address
    ? `
<div class="info-row">
<div class="label">Adresse</div>
<div class="value">${escapeHTML(client.address)}</div>
</div>
`
    : ""
}

${
  client.email
    ? `
<div class="info-row">
<div class="label">Email</div>
<div class="value">${escapeHTML(client.email)}</div>
</div>
`
    : ""
}

${
  client.phone
    ? `
<div class="info-row">
<div class="label">Téléphone</div>
<div class="value">${escapeHTML(client.phone)}</div>
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
        // OTHER SERVICES
        // =================================================

        if (
          [
            "google_review",
            "instagram",
            "whatsapp",
            "tiktok",
            "menu",
            "custom_link"
          ].includes(
            service.service_type
          )
        ) {

          if (service.destination_url) {
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
<body style="font-family:Arial;text-align:center;padding:50px;">
<h2>TAPNIVO</h2>
<p>Aucune destination configurée.</p>
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
<body style="font-family:Arial;text-align:center;padding:50px;">
<h2>TAPNIVO</h2>
<p>Service configuré mais aucune action disponible.</p>
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
<body style="font-family:Arial;text-align:center;padding:50px;">
<h2>Erreur serveur</h2>
<p>${escapeHTML(error.message)}</p>
</body>
</html>
`,
          500
        );
      }
    }

// =====================================================
// CLIENT CONTACT VCF
// IMPORTANT: قبل /contact/:service
// =====================================================

    if (
      url.pathname.startsWith("/contact/client/") &&
      url.pathname.endsWith(".vcf")
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
            status: 404,
            headers: {
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
            .bind(slug)
            .first();

        if (!client) {
          return new Response(
            "Client introuvable.",
            {
              status: 404,
              headers: {
                "Content-Type":
                  "text/plain; charset=UTF-8"
              }
            }
          );
        }

        const vcfEscape = (value) => {

          if (
            value === null ||
            value === undefined
          ) {
            return "";
          }

          return String(value)
            .replace(/\\/g, "\\\\")
            .replace(/\r?\n/g, "\\n")
            .replace(/;/g, "\\;")
            .replace(/,/g, "\\,");
        };

        const name =
          vcfEscape(client.name || "");

        const phone =
          vcfEscape(client.phone || "");

        const whatsapp =
          vcfEscape(client.whatsapp || "");

        const email =
          vcfEscape(client.email || "");

        const website =
          vcfEscape(client.website || "");

        const address =
          vcfEscape(client.address || "");

        const profession =
          vcfEscape(client.profession || "");

        const photo =
          client.photo_url
            ? String(client.photo_url).trim()
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
          lines.join("\r\n");

        return new Response(
          vcard,
          {
            status: 200,
            headers: {
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
            status: 500,
            headers: {
              "Content-Type":
                "text/plain; charset=UTF-8"
            }
          }
        );
      }
    }

// =====================================================
// SERVICE CONTACT VCF
// /contact/SERVICECODE.vcf
// =====================================================

    if (
      url.pathname.startsWith("/contact/") &&
      !url.pathname.startsWith("/contact/client/") &&
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
            status: 404,
            headers: {
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
                service_code,
                service_type,
                status,
                client_id
              FROM services
              WHERE service_code = ?
              LIMIT 1
            `)
            .bind(serviceCode)
            .first();

        if (!service) {
          return new Response(
            "Service introuvable.",
            {
              status: 404,
              headers: {
                "Content-Type":
                  "text/plain; charset=UTF-8"
              }
            }
          );
        }

        if (
          service.status !== "active" ||
          service.service_type !== "digital_card"
        ) {
          return new Response(
            "Service indisponible.",
            {
              status: 404,
              headers: {
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
            .bind(service.client_id)
            .first();

        if (!client) {
          return new Response(
            "Client introuvable.",
            {
              status: 404,
              headers: {
                "Content-Type":
                  "text/plain; charset=UTF-8"
              }
            }
          );
        }

        const vcfEscape = (value) => {

          if (
            value === null ||
            value === undefined
          ) {
            return "";
          }

          return String(value)
            .replace(/\\/g, "\\\\")
            .replace(/\r?\n/g, "\\n")
            .replace(/;/g, "\\;")
            .replace(/,/g, "\\,");
        };

        const name =
          vcfEscape(client.name || "");

        const phone =
          vcfEscape(client.phone || "");

        const whatsapp =
          vcfEscape(client.whatsapp || "");

        const email =
          vcfEscape(client.email || "");

        const website =
          vcfEscape(client.website || "");

        const address =
          vcfEscape(client.address || "");

        const profession =
          vcfEscape(client.profession || "");

        const photo =
          client.photo_url
            ? String(client.photo_url).trim()
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
          lines.join("\r\n");

        return new Response(
          vcard,
          {
            status: 200,
            headers: {
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
            status: 500,
            headers: {
              "Content-Type":
                "text/plain; charset=UTF-8"
            }
          }
        );
      }
    }

// =====================================================
// PUBLIC CLIENT PROFILE
// /client/SLUG
// =====================================================

    if (
      url.pathname.startsWith("/client/")
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
            .bind(slug)
            .first();

        if (!client) {
          return html(
            "Client introuvable",
            404
          );
        }

        const photoHTML =
          client.photo_url
            ? `
<img
class="profile-photo"
src="${escapeHTML(client.photo_url)}"
alt="${escapeHTML(client.name)}"
loading="lazy">
`
            : `
<div class="avatar">👤</div>
`;

        const buttons = [];

        if (client.phone) {
          buttons.push(`
<a class="button"
href="tel:${escapeHTML(client.phone)}">
📞 Appeler
</a>
`);
        }

        if (client.whatsapp) {

          const whatsapp =
            String(client.whatsapp)
              .replace(/[^0-9]/g, "");

          if (whatsapp) {
            buttons.push(`
<a class="button"
href="https://wa.me/${escapeHTML(whatsapp)}"
target="_blank"
rel="noopener">
💬 WhatsApp
</a>
`);
          }
        }

        const contactUrl =
          `${url.origin}/contact/client/${encodeURIComponent(
            client.slug
          )}.vcf`;

        buttons.push(`
<a class="button contact"
href="${escapeHTML(contactUrl)}">
👤 Ajouter aux contacts
</a>
`);

        if (client.email) {
          buttons.push(`
<a class="button secondary"
href="mailto:${escapeHTML(client.email)}">
✉️ Email
</a>
`);
        }

        if (client.instagram) {
          buttons.push(`
<a class="button secondary"
href="${escapeHTML(client.instagram)}"
target="_blank"
rel="noopener">
📸 Instagram
</a>
`);
        }

        if (client.facebook) {
          buttons.push(`
<a class="button secondary"
href="${escapeHTML(client.facebook)}"
target="_blank"
rel="noopener">
📘 Facebook
</a>
`);
        }

        if (client.tiktok) {
          buttons.push(`
<a class="button secondary"
href="${escapeHTML(client.tiktok)}"
target="_blank"
rel="noopener">
🎵 TikTok
</a>
`);
        }

        if (client.linkedin) {
          buttons.push(`
<a class="button secondary"
href="${escapeHTML(client.linkedin)}"
target="_blank"
rel="noopener">
💼 LinkedIn
</a>
`);
        }

        if (client.maps) {
          buttons.push(`
<a class="button secondary"
href="${escapeHTML(client.maps)}"
target="_blank"
rel="noopener">
📍 Google Maps
</a>
`);
        }

        if (client.website) {
          buttons.push(`
<a class="button secondary"
href="${escapeHTML(client.website)}"
target="_blank"
rel="noopener">
🌐 Site web
</a>
`);
        }

        if (client.reviews) {
          buttons.push(`
<a class="button secondary"
href="${escapeHTML(client.reviews)}"
target="_blank"
rel="noopener">
⭐ Google Reviews
</a>
`);
        }

        return html(`
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#4f46e5">
<title>${escapeHTML(client.name)} | TAPNIVO</title>
<style>
*{box-sizing:border-box;}
body{
margin:0;
font-family:Arial,Helvetica,sans-serif;
background:linear-gradient(135deg,#f5f7fb,#eef2ff);
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
box-shadow:0 18px 50px rgba(0,0,0,.09);
}
.logo{
font-size:21px;
font-weight:800;
margin-bottom:28px;
}
.logo span{color:#4f46e5;}
.profile-photo{
width:120px;
height:120px;
border-radius:50%;
object-fit:cover;
display:block;
margin:0 auto 20px;
border:4px solid #eef2ff;
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
.button.contact{background:#111827;}
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
border-bottom:1px solid #eeeeee;
}
.info-row:last-child{border-bottom:0;}
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
${escapeHTML(client.name)}
</h1>

${
  client.profession
    ? `
<div class="profession">
${escapeHTML(client.profession)}
</div>
`
    : ""
}

${
  client.bio
    ? `
<div class="bio">
${escapeHTML(client.bio)}
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
<div class="label">Email</div>
<div class="value">
${escapeHTML(client.email)}
</div>
</div>
`
    : ""
}

${
  client.phone
    ? `
<div class="info-row">
<div class="label">Téléphone</div>
<div class="value">
${escapeHTML(client.phone)}
</div>
</div>
`
    : ""
}

${
  client.address
    ? `
<div class="info-row">
<div class="label">Adresse</div>
<div class="value">
${escapeHTML(client.address)}
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
