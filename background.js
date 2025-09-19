// This listener fires when a tab is updated (e.g., new URL loaded)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // We only want to act when the tab is fully loaded and has a URL
  if (
    changeInfo.status === "complete" &&
    tab.url &&
    tab.url.startsWith("http")
  ) {
    fetch("http://127.0.0.1:5000/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url }),
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.is_phishing) {
          // If phishing is detected, first inject the content script
          chrome.scripting
            .executeScript({
              target: { tabId: tabId },
              files: ["content.js"],
            })
            .then(() => {
              // After the script is injected, send the message to display the banner
              chrome.tabs.sendMessage(tabId, { is_phishing: true });
            })
            .catch((err) =>
              console.error("PhishGuard: Script injection failed: " + err)
            );
        }
      })
      .catch((error) => {
        console.error("PhishGuard: Error calling API:", error);
      });
  }
});
