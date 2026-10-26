

document.addEventListener("DOMContentLoaded", () => {
    // Add a smooth entrance class after the page loads.
    document.body.classList.add("page-ready");

    // Password visibility toggle for password inputs.
    document.querySelectorAll('input[type="password"]').forEach((input) => {
        const wrapper = document.createElement("div");
        wrapper.className = "password-wrapper";
        input.parentNode.insertBefore(wrapper, input);
        wrapper.appendChild(input);

        const toggle = document.createElement("button");
        toggle.type = "button";
        toggle.className = "password-toggle";
        toggle.textContent = "Show";
        toggle.setAttribute("aria-label", "Show password");

        wrapper.appendChild(toggle);

        toggle.addEventListener("click", () => {
            const isHidden = input.type === "password";
            input.type = isHidden ? "text" : "password";
            toggle.textContent = isHidden ? "Hide" : "Show";
            toggle.setAttribute(
                "aria-label",
                isHidden ? "Hide password" : "Show password"
            );
            input.focus();
        });
    });

    // Show the selected filename beside a file input.
    document.querySelectorAll('input[type="file"]').forEach((input) => {
        input.addEventListener("change", () => {
            const file = input.files && input.files[0];
            const output = input
                .closest("form")
                ?.querySelector("[data-file-name]");

            if (output) {
                output.textContent = file
                    ? `Selected: ${file.name}`
                    : "No file selected";
            }
        });
    });

    // Prevent accidental repeated submissions and show loading text.
    document.querySelectorAll("form").forEach((form) => {
        form.addEventListener("submit", () => {
            if (!form.checkValidity()) return;

            const button = form.querySelector(
                'button[type="submit"], input[type="submit"]'
            );

            if (!button || button.dataset.loading === "true") return;

            button.dataset.loading = "true";
            button.classList.add("is-loading");

            if (button.tagName === "BUTTON") {
                button.dataset.originalText = button.textContent;
                button.textContent = "Please wait…";
            }
        });
    });

    // Copy a share link when a copy button is present.
    document.querySelectorAll("[data-copy-target]").forEach((button) => {
        button.addEventListener("click", async () => {
            const selector = button.getAttribute("data-copy-target");
            const field = selector ? document.querySelector(selector) : null;
            if (!field) return;

            try {
                await navigator.clipboard.writeText(
                    field.value || field.textContent.trim()
                );
                const original = button.textContent;
                button.textContent = "Copied!";
                window.setTimeout(() => {
                    button.textContent = original;
                }, 1600);
            } catch {
                if (field.select) {
                    field.select();
                }
            }
        });
    });

    // Confirm destructive actions only when explicitly marked.
    document.querySelectorAll("[data-confirm]").forEach((element) => {
        element.addEventListener("click", (event) => {
            const message =
                element.getAttribute("data-confirm") ||
                "Are you sure you want to continue?";

            if (!window.confirm(message)) {
                event.preventDefault();
            }
        });
    });
});
