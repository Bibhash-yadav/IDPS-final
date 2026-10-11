chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) {
    console.log("IDPS Shield monitoring navigation to:", details.url);
    // Communicates with FastAPI backend for real-time blocking/warning
  }
});