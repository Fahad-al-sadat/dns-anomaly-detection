//unique rule ID generation using timestamp
function generateRuleId() 
{
  return Math.floor(Date.now() / 1000);
}

function blockDomain(domain) {

  chrome.declarativeNetRequest.getDynamicRules((existingRules) => {

    const removeIds = existingRules.map(rule => rule.id);

    chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: removeIds,
      addRules: [{
        id: generateRuleId(),
        priority: 1,
        action: { type: "block" },
        condition: {
          urlFilter: domain,
          resourceTypes: ["main_frame"]
        }
      }]
    });

  });
}

const WHITELIST = [
  "127.0.0.1",
  "localhost"
];

chrome.webNavigation.onBeforeNavigate.addListener(
  function(details) {

    const url = new URL(details.url);
    const domain = url.hostname;

    if (WHITELIST.includes(domain)) {
    return;
}

    fetch("http://127.0.0.1:8000/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ip: "detect_from_server",
        domain: domain
      })
    })
    .then(response => response.json())
    .then(data => {
      if (data.status === "ANOMALY") {
        console.log("Blocking:", domain);
        blockDomain(domain);
      }
    })
    .catch(err => console.log("API error:", err));

  }
);