
const params = new URLSearchParams(window.location.search);
const requestedUrl = params.get("url") || "";
const reasonText = params.get("reason") || "No detailed reason was provided.";

document.getElementById("requestedUrl").textContent = requestedUrl;

const list = document.getElementById("reasons");

for (const reason of reasonText.split(";").filter(Boolean)) {
  const item = document.createElement("li");
  item.textContent = reason;
  list.appendChild(item);
}

document.getElementById("backButton").addEventListener("click", () => {
  if (history.length > 1) {
    history.back();
  } else {
    window.close();
  }
});

document.getElementById("continueButton").addEventListener("click", () => {
  if (!/^https?:\/\//i.test(requestedUrl)) {
    return;
  }

  const confirmed = window.confirm(
    "The IDPS engine blocked this website. Continuing may be unsafe. Do you want to continue?"
  );

  if (confirmed) {
    window.location.href = requestedUrl;
  }
});
