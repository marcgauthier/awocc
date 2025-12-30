(function () {
  const loginForm = document.querySelector("[data-admin-login]");
  if (loginForm) {
    loginForm.addEventListener("submit", (event) => {
      event.preventDefault();
      const data = Object.fromEntries(new FormData(loginForm));
      fetch("/api/admin/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: data.username,
          password: data.password,
        }),
      })
        .then((res) => {
          if (!res.ok) {
            throw new Error("invalid");
          }
          window.location.href = "/admin/dashboard";
        })
        .catch(() => {
          const status = document.querySelector("[data-login-status]");
          if (status) {
            status.textContent = "Login failed";
            status.style.display = "block";
          }
        });
    });
  }

  const adminShell = document.querySelector("[data-admin-shell]");
  if (adminShell) {
    loadAdminLists();
    loadSettings();
    bindForm("blog", "/api/admin/blog");
    bindForm("vlog", "/api/admin/vlog");
    bindForm("news", "/api/admin/news");
    bindSettingsForm();

    const logout = document.querySelector("[data-admin-logout]");
    if (logout) {
      logout.addEventListener("click", () => {
        fetch("/api/admin/logout", { method: "POST" }).then(() => {
          window.location.href = "/admin/login";
        });
      });
    }
  }

  function loadAdminLists() {
    loadList("blog", "/api/admin/blog");
    loadList("vlog", "/api/admin/vlog");
    loadList("news", "/api/admin/news");
  }

  function loadSettings() {
    fetch("/api/admin/settings")
      .then((res) => {
        if (res.status === 401) {
          window.location.href = "/admin/login";
          throw new Error("unauthorized");
        }
        return res.json();
      })
      .then((info) => {
        const form = document.querySelector("[data-settings-form]");
        if (!form || !info) {
          return;
        }
        form.querySelector("[name=email]").value = info.email || "";
        form.querySelector("[name=phone]").value = info.phone || "";
        const wordsInput = form.querySelector("[name=blog_excerpt_words]");
        if (wordsInput) {
          wordsInput.value = info.blog_excerpt_words || "";
        }
        const linkedInInput = form.querySelector("[name=linkedin_url]");
        if (linkedInInput) {
          linkedInInput.value = info.linkedin_url || "";
        }
        const facebookInput = form.querySelector("[name=facebook_url]");
        if (facebookInput) {
          facebookInput.value = info.facebook_url || "";
        }
        const instagramInput = form.querySelector("[name=instagram_url]");
        if (instagramInput) {
          instagramInput.value = info.instagram_url || "";
        }
      })
      .catch(() => {});
  }

  function loadList(kind, url) {
    fetch(url)
      .then((res) => {
        if (res.status === 401) {
          window.location.href = "/admin/login";
          throw new Error("unauthorized");
        }
        return res.json();
      })
      .then((items) => renderAdminList(kind, items))
      .catch(() => {});
  }

  function renderAdminList(kind, items) {
    const target = document.querySelector(`[data-${kind}-list]`);
    if (!target || !Array.isArray(items)) {
      return;
    }
    target.innerHTML = "";
    items.forEach((item) => {
      const row = document.createElement("div");
      row.className = "admin-list-row";

      const button = document.createElement("button");
      button.type = "button";
      button.className = "admin-list-item";
      button.textContent = `${item.title} (${item.published ? "published" : "draft"})`;
      button.addEventListener("click", () => populateForm(kind, item));

      const deleteBtn = document.createElement("button");
      deleteBtn.type = "button";
      deleteBtn.className = "btn btn-ghost admin-delete";
      deleteBtn.textContent = "Delete";
      deleteBtn.addEventListener("click", (event) => {
        event.stopPropagation();
        if (!window.confirm("Delete this item?")) {
          return;
        }
        deleteItem(kind, item.id);
      });

      row.appendChild(button);
      row.appendChild(deleteBtn);
      target.appendChild(row);
    });
  }

  function bindForm(kind, url) {
    const form = document.querySelector(`[data-${kind}-form]`);
    if (!form) {
      return;
    }
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const data = Object.fromEntries(new FormData(form));
      const payload = buildPayload(kind, data);
      const id = data.id;
      const method = id ? "PUT" : "POST";
      const endpoint = id ? `${url}/${id}` : url;
      fetch(endpoint, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      })
        .then((res) => {
          if (!res.ok) {
            throw new Error("save failed");
          }
          form.reset();
          form.querySelector("[name=id]").value = "";
          loadAdminLists();
        })
        .catch(() => {});
    });
  }

  function bindSettingsForm() {
    const form = document.querySelector("[data-settings-form]");
    if (!form) {
      return;
    }
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const data = Object.fromEntries(new FormData(form));
      const words = parseInt(data.blog_excerpt_words, 10);
      fetch("/api/admin/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: data.email || "",
          phone: data.phone || "",
          blog_excerpt_words: Number.isFinite(words) ? words : 0,
          linkedin_url: data.linkedin_url || "",
          facebook_url: data.facebook_url || "",
          instagram_url: data.instagram_url || "",
        }),
      })
        .then((res) => {
          if (!res.ok) {
            throw new Error("save failed");
          }
          loadSettings();
        })
        .catch(() => {});
    });
  }

  function populateForm(kind, item) {
    const form = document.querySelector(`[data-${kind}-form]`);
    if (!form) {
      return;
    }
    form.querySelector("[name=id]").value = item.id || "";
    form.querySelector("[name=title]").value = item.title || "";
    const slugInput = form.querySelector("[name=slug]");
    if (slugInput) {
      slugInput.value = item.slug || "";
    }
    if (form.querySelector("[name=description]")) {
      form.querySelector("[name=description]").value = item.description || "";
    }
    const bodyInput = form.querySelector("[name=body]");
    if (bodyInput) {
      bodyInput.value = item.body || "";
    }
    if (form.querySelector("[name=youtube_url]")) {
      form.querySelector("[name=youtube_url]").value = item.youtube_url || "";
    }
    if (form.querySelector("[name=image_url]")) {
      form.querySelector("[name=image_url]").value = item.image_url || "";
    }
    form.querySelector("[name=published]").checked = !!item.published;
    form.querySelector("[name=published_at]").value = item.published_at || "";
  }

  function deleteItem(kind, id) {
    if (!id) {
      return;
    }
    fetch(`/api/admin/${kind}/${id}`, { method: "DELETE" })
      .then((res) => {
        if (!res.ok) {
          throw new Error("delete failed");
        }
        loadAdminLists();
      })
      .catch(() => {});
  }

  function buildPayload(kind, data) {
    const payload = {
      title: data.title || "",
      published: data.published === "on",
      published_at: data.published_at || "",
    };
    if (kind === "blog") {
      payload.body = data.body || "";
    }
    if (kind === "vlog") {
      payload.description = data.description || "";
      payload.youtube_url = data.youtube_url || "";
      payload.image_url = data.image_url || "";
    }
    if (kind === "news") {
      payload.slug = data.slug || "";
      payload.description = data.description || "";
      payload.body = data.body || "";
    }
    return payload;
  }
})();
