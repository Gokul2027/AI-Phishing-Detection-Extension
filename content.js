// This listener waits for a message from the background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Check if the message indicates a phishing attempt
  if (request.is_phishing) {
    // Create the warning banner element
    const banner = document.createElement("div");
    banner.style.position = "fixed";
    banner.style.top = "0";
    banner.style.left = "0";
    banner.style.width = "100%";
    banner.style.backgroundColor = "#ff4d4d"; // A bright red color
    banner.style.color = "white";
    banner.style.padding = "15px";
    banner.style.textAlign = "center";
    banner.style.zIndex = "999999"; // Ensure it's on top of everything
    banner.style.fontSize = "18px";
    banner.style.fontFamily = "Arial, sans-serif";
    banner.style.borderBottom = "2px solid #cc0000";

    banner.innerHTML =
      "<strong>⚠️ PHISHING WARNING:</strong> This website is flagged as potentially unsafe. Proceed with extreme caution.";

    // Add the banner to the top of the page's body
    document.body.prepend(banner);
  }
});
