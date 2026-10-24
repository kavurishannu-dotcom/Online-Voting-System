document.addEventListener("DOMContentLoaded", () => {
    // Keep flash messages visually stable after page load.
    window.setTimeout(() => {
        document.querySelectorAll(".alert").forEach((alert) => {
            alert.style.opacity = "0.95";
        });
    }, 50);

    // Prevent accidental double submission.
    document.querySelectorAll("form").forEach((form) => {
        form.addEventListener("submit", () => {
            const button = form.querySelector(
                'button[type="submit"], button.btn'
            );

            if (button && !form.dataset.noLock) {
                button.disabled = true;

                window.setTimeout(() => {
                    button.disabled = false;
                }, 4000);
            }
        });
    });
});

// Open/close the dashboard sidebar on smaller screens.
function toggleSidebar() {
    const sidebar = document.getElementById("sidebar");

    if (sidebar) {
        sidebar.classList.toggle("open");
    }
}

// Close the mobile sidebar after selecting a navigation item.
document.addEventListener("click", (event) => {
    const sidebar = document.getElementById("sidebar");

    if (!sidebar) {
        return;
    }

    const link = event.target.closest(".sidebar-nav a");

    if (link && window.innerWidth <= 850) {
        sidebar.classList.remove("open");
    }
});
