const ctx = document.getElementById('anomalyChart').getContext('2d');
const anomalyChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            data: [],
            borderColor: '#ef4444',
            backgroundColor: 'rgba(239, 68, 68, 0.1)',
            fill: true, tension: 0.4, pointRadius: 0
        }]
    },
    options: { 
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: { display: false }, y: { grid: { color: 'rgba(255,255,255,0.03)' } } }
    }
});

async function updateDashboard() {
    try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        
        document.getElementById('stat-total').innerText = data.total_requests;
        document.getElementById('stat-anomalies').innerText = data.anomalies;
        document.getElementById('stat-threat').innerText = data.threat_level + '%';

        //Chart
        anomalyChart.data.labels.push("");
        anomalyChart.data.datasets[0].data.push(data.anomalies);
        if(anomalyChart.data.labels.length > 20) {
            anomalyChart.data.labels.shift();
            anomalyChart.data.datasets[0].data.shift();
        }
        anomalyChart.update('none');

        //Table
document.getElementById('log-body').innerHTML = data.logs.map(log => {
    const probability = log.ml_prob || 0;
    const percentage = (probability * 100).toFixed(0);
    const scoreClass = probability > 0.7 ? 'text-red-500' : (probability > 0.4 ? 'text-orange-400' : 'text-emerald-400');

    return `
        <tr class="border-b border-white/5 hover:bg-white/[0.01]">
            <td class="p-4 text-gray-500 font-mono text-xs">${log.time}</td>
            <td class="p-4 text-gray-300 text-xs">${log.ip}</td>
            <td onclick="${log.status === 'ANOMALY' ? `window.location.href='/blocked?url=${log.domain}'` : `window.open('http://${log.domain}', '_blank')`}" 
    class="p-4 w-[35%] text-blue-400 font-semibold text-xs cursor-pointer hover:underline truncate">
    ${log.domain}
</td>
            
            <td class="p-4 text-center">
                <span class="inline-block px-2 py-1 rounded text-[10px] font-bold ${
                    log.status === 'ANOMALY' 
                    ? 'bg-red-500/10 text-red-500 border border-red-500/20 anomaly-blink' 
                    : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                }">${log.status}</span>
            </td>

            <td class="p-4 text-right">
                <div class="inline-block text-right">
                    <span class="font-mono text-xs ${scoreClass}">${percentage}%</span>
                    <div class="w-16 bg-white/5 h-1 rounded-full mt-1 overflow-hidden">
                        <div class="h-full ${log.status === 'ANOMALY' ? 'bg-red-500' : 'bg-emerald-500'}" 
                             style="width: ${percentage}%"></div>
                    </div>
                </div>
            </td>
        </tr>
    `;
}).join('');
    } catch (e) { console.error("Error updating dashboard:", e); }
}

async function confirmReset() {
    if (confirm("Clear all logs?")) {
        await fetch('/api/reset', { method: 'POST' });
        anomalyChart.data.labels = [];
        anomalyChart.data.datasets[0].data = [];
        anomalyChart.update();
        updateDashboard();
    }
}

setInterval(updateDashboard, 2000);
updateDashboard();

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const backdrop = document.getElementById('backdrop');
    
    sidebar.classList.toggle('sidebar-open');
    backdrop.classList.toggle('hidden');
}

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        document.getElementById('sidebar').classList.remove('sidebar-open');
        document.getElementById('backdrop').classList.add('hidden');
    }
});

function openCheckModel() {
    toggleSidebar();
    document.getElementById('checkModel').classList.remove('hidden');
}

function closeCheckModel() {
    document.getElementById('checkModel').classList.add('hidden');
    document.getElementById('scanResult').classList.add('hidden');
    document.getElementById('manualDomain').value = '';
}

async function runManualCheck() {
    const domain = document.getElementById('manualDomain').value;
    if (!domain) return alert("Please enter a domain!");

    const btn = document.getElementById('scanBtn');
    const resultArea = document.getElementById('scanResult');
    
    // UI Loading State
    btn.disabled = true;
    btn.innerText = "ANALYZING...";
    resultArea.classList.add('hidden');

    try {
        // "/check"
        const response = await fetch('/check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: domain, ip: "User-Input" })
        });

        const data = await response.json();

        // showing_Result
        resultArea.classList.remove('hidden');
        resultArea.classList.remove('animate-pulse');
        
        document.getElementById('resDomain').innerText = domain;
        const prob = data.ml_prob || 0;
        const score = (prob * 100).toFixed(0);
        
        const resStatus = document.getElementById('resStatus');
        const resBar = document.getElementById('resBar');
        
        resStatus.innerText = data.status;
        document.getElementById('resScore').innerText = score + "%";
        
        if(data.status === 'ANOMALY') {
            resStatus.className = "font-bold text-xs px-2 py-1 rounded bg-red-500/20 text-red-500";
            resBar.className = "h-full bg-red-500";
        } else {
            resStatus.className = "font-bold text-xs px-2 py-1 rounded bg-emerald-500/20 text-emerald-400";
            resBar.className = "h-full bg-emerald-500";
        }
        
        resBar.style.width = score + "%";

    } catch (error) {
        alert("Scan failed. Is the server running?");
    } finally {
        btn.disabled = false;
        btn.innerText = "START SCAN";
    }
}

// ১. ক্যালকুলেটর মডাল ওপেন ও ক্লোজ ফাংশন
function openIpModal() {
    toggleSidebar(); // মেনু বন্ধ হবে
    document.getElementById('ipModal').classList.remove('hidden');
}

function closeIpModal() {
    document.getElementById('ipModal').classList.add('hidden');
    document.getElementById('ipResult').classList.add('hidden');
    document.getElementById('ipInput').value = '';
}

// ২. ক্যালকুলেটর লজিক (সিম্পল ডেমো)
function calculateIP() {
    const input = document.getElementById('ipInput').value.trim();
    const resultDiv = document.getElementById('ipResult');
    
    if (!input.includes('/')) return alert("Use CIDR format: 192.168.1.1/24");

    const [ip, cidr] = input.split('/');
    const mask = parseInt(cidr);
    
    // অ্যাডভান্সড ক্যালকুলেশন
    const totalHosts = Math.pow(2, 32 - mask);
    const subnetMask = Array(4).fill(0).map((_, i) => {
        const bits = Math.min(Math.max(mask - i * 8, 0), 8);
        return 256 - Math.pow(2, 8 - bits);
    }).join('.');

    resultDiv.classList.remove('hidden');
    resultDiv.innerHTML = `
        <div class="grid grid-cols-2 gap-2 text-[10px]">
            <span class="text-gray-500">Subnet Mask:</span> <span class="text-emerald-400 font-bold">${subnetMask}</span>
            <span class="text-gray-500">Total IP's:</span> <span class="text-blue-400 font-bold">${totalHosts.toLocaleString()}</span>
            <span class="text-gray-500">Usable Hosts:</span> <span class="text-orange-400 font-bold">${totalHosts > 2 ? totalHosts - 2 : 0}</span>
            <span class="text-gray-500">CIDR Range:</span> <span class="text-purple-400 font-bold">/${mask}</span>
            
        </div>
    `;
}

// --- নতুন ফিচার: Warning Modal Logic ---

/**
 * এনোমালি ডোমেইনে ক্লিক করলে এই ফাংশনটি কল হবে
 * @param {string} domain 
 */
function showWarning(domain) {
    const warnModal = document.getElementById('warningModal');
    const warnDomain = document.getElementById('warnDomain');
    const proceedLink = document.getElementById('proceedLink');

    if (warnModal && warnDomain && proceedLink) {
        warnDomain.innerText = domain;
        
        // ডোমেইন যদি http দিয়ে শুরু না হয় তবে তা যোগ করে দেয়া
        const fullUrl = domain.startsWith('http') ? domain : `http://${domain}`;
        proceedLink.href = fullUrl;
        
        warnModal.classList.remove('hidden');
    }
}

/**
 * ওয়ার্নিং পপ-আপ বন্ধ করার ফাংশন
 */
function closeWarning() {
    const warnModal = document.getElementById('warningModal');
    if (warnModal) {
        warnModal.classList.add('hidden');
    }
}

// Esc বাটন চাপলে ওয়ার্নিং পপ-আপ বন্ধ হওয়া
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeWarning();
    }
});