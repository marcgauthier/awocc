(function () {
  const html = document.documentElement;
  const storedLang = localStorage.getItem("awocc-lang");
  const browserLang = (navigator.language || "en").toLowerCase().startsWith("fr") ? "fr" : "en";
  const activeLang = storedLang || browserLang;
  html.dataset.lang = activeLang;

  const langToggle = document.querySelector("[data-lang-toggle]");
  if (langToggle) {
    langToggle.addEventListener("click", () => {
      const nextLang = html.dataset.lang === "en" ? "fr" : "en";
      html.dataset.lang = nextLang;
      localStorage.setItem("awocc-lang", nextLang);
    });
  }

  const navToggle = document.querySelector("[data-nav-toggle]");
  const nav = document.getElementById("siteNav");
  if (navToggle && nav) {
    navToggle.addEventListener("click", () => {
      nav.classList.toggle("open");
    });
  }

  document.querySelectorAll("[data-year]").forEach((node) => {
    node.textContent = new Date().getFullYear();
  });
})();
