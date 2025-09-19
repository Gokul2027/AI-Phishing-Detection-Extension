// This script listens for a message from the background script.
// If it receives a phishing alert, it creates a more intuitive modal dialog.

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Check if the message is a phishing alert
  if (request.is_phishing) {
    // Prevent the banner from being added multiple times
    if (document.getElementById("phishguard-modal-overlay")) {
      return;
    }

    // --- Create the Modal Elements ---

    // 1. The semi-transparent background overlay
    const overlay = document.createElement("div");
    overlay.id = "phishguard-modal-overlay";
    Object.assign(overlay.style, {
      position: "fixed",
      top: "0",
      left: "0",
      width: "100vw",
      height: "100vh",
      backgroundColor: "rgba(0, 0, 0, 0.7)",
      zIndex: "2147483647", // Max z-index to ensure it's on top
      display: "flex",
      justifyContent: "center",
      alignItems: "center",
      backdropFilter: "blur(5px)", // Modern blur effect
    });

    // 2. The main warning modal box
    const modal = document.createElement("div");
    modal.id = "phishguard-modal-content";
    Object.assign(modal.style, {
      backgroundColor: "#ffffff",
      padding: "40px",
      borderRadius: "12px",
      boxShadow: "0 10px 25px rgba(0, 0, 0, 0.2)",
      textAlign: "center",
      maxWidth: "500px",
      width: "90%",
      fontFamily: "Arial, sans-serif",
      borderTop: "8px solid #d9534f",
      animation: "fadeIn 0.3s ease-in-out",
    });

    // 3. The warning icon (SVG for high quality)
    const icon = document.createElement("div");
    icon.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="60" height="60" viewBox="0 0 24 24" fill="none" stroke="#d9534f" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;

    // 4. The main headline
    const title = document.createElement("h1");
    title.textContent = "Security Alert";
    Object.assign(title.style, {
      color: "#333333",
      margin: "20px 0 10px 0",
      fontSize: "28px",
    });

    // 5. The descriptive paragraph
    const message = document.createElement("p");
    message.textContent =
      "This website has been flagged for characteristics commonly associated with phishing. Entering any sensitive information is not recommended.";
    Object.assign(message.style, {
      color: "#666666",
      fontSize: "16px",
      lineHeight: "1.5",
    });

    // 6. The "Go Back" button (Primary action)
    const backButton = document.createElement("button");
    backButton.textContent = "Go Back to Safety";
    Object.assign(backButton.style, {
      backgroundColor: "#28a745",
      color: "white",
      border: "none",
      padding: "12px 25px",
      borderRadius: "6px",
      fontSize: "16px",
      fontWeight: "bold",
      cursor: "pointer",
      marginTop: "30px",
      marginRight: "10px",
      transition: "background-color 0.2s",
    });
    backButton.onmouseover = () =>
      (backButton.style.backgroundColor = "#218838");
    backButton.onmouseout = () =>
      (backButton.style.backgroundColor = "#28a745");
    backButton.onclick = () => window.history.back();

    // 7. The "Proceed" button (Secondary action)
    const proceedButton = document.createElement("button");
    proceedButton.textContent = "Proceed with Caution";
    Object.assign(proceedButton.style, {
      backgroundColor: "#f0f0f0",
      color: "#333",
      border: "1px solid #ccc",
      padding: "12px 25px",
      borderRadius: "6px",
      fontSize: "16px",
      cursor: "pointer",
      transition: "background-color 0.2s",
    });
    proceedButton.onmouseover = () =>
      (proceedButton.style.backgroundColor = "#e0e0e0");
    proceedButton.onmouseout = () =>
      (proceedButton.style.backgroundColor = "#f0f0f0");
    proceedButton.onclick = () => overlay.remove();

    // --- Assemble and Display the Modal ---
    modal.appendChild(icon);
    modal.appendChild(title);
    modal.appendChild(message);
    modal.appendChild(backButton);
    modal.appendChild(proceedButton);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);

    // Add a simple fade-in animation using CSS keyframes
    const styleSheet = document.createElement("style");
    styleSheet.type = "text/css";
    styleSheet.innerText = `@keyframes fadeIn { from { opacity: 0; transform: scale(0.95); } to { opacity: 1; transform: scale(1); } }`;
    document.head.appendChild(styleSheet);
  }
});
