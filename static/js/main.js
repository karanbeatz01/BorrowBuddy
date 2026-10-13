// Keep password entry private by default, while allowing users to check for typos.
document.querySelectorAll("[data-password-toggle]").forEach((button) => {
    button.addEventListener("click", () => {
        const field = button.closest(".password-field").querySelector("[data-password-input]");
        const shouldShow = field.type === "password";

        field.type = shouldShow ? "text" : "password";
        button.textContent = shouldShow ? "Hide" : "Show";
        button.setAttribute("aria-label", shouldShow ? "Hide password" : "Show password");
        button.setAttribute("aria-pressed", String(shouldShow));
    });
});
