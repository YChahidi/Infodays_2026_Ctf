/* ═══════════════════════════════════════════════════════════
   Infodays 2026 — platform logic
   ═══════════════════════════════════════════════════════════ */

// ═══ Challenge data (from challenges_table.tex) ═══════════════
const CHALLENGES = [
    // WEB
    { name: "VIP Access",              cat: "Web",        diff: "easy",    flags: 1, pts: 100,  desc: "Cookie-based authentication bypass" },
    { name: "The Secret Archive",      cat: "Web",        diff: "easy",    flags: 1, pts: 100,  desc: "Restricted file archive with layered access control" },
    { name: "Ping-o-Matic",            cat: "Web",        diff: "hard",    flags: 1, pts: 400,  desc: "Network ping utility with input filtering" },
    { name: "Scout Database",          cat: "Web",        diff: "hard",    flags: 1, pts: 400,  desc: "Player registration database with strict input validation" },
    { name: "VAR Check Bro",           cat: "Web",        diff: "hard",    flags: 1, pts: 400,  desc: "Video assistant referee with internal review service" },
    { name: "Stadium CI",              cat: "Web",        diff: "hard",    flags: 1, pts: 400,  desc: "Continuous integration console with authentication layer" },
    { name: "Referee Decision System", cat: "Web",        diff: "hard",    flags: 3, pts: 500,  desc: "Multi-vector match decision management system" },
    { name: "Man City",                cat: "Web",        diff: "insane",  flags: 8, pts: 1500, desc: "Progressive multi-vulnerability web application" },
    { name: "Stadium DeFi",            cat: "Web",        diff: "vhard",   flags: 1, pts: 750,  desc: "Smart contract betting platform on Ethereum" },
    // PWN
    { name: "VAR Review",              cat: "Pwn",        diff: "medium",  flags: 1, pts: 300,  desc: "Binary with improper string handling" },
    { name: "VAR Replay Buffer",       cat: "Pwn",        diff: "hard",    flags: 1, pts: 500,  desc: "Hardened replay buffer manager with hidden functionality" },
    { name: "SHANKS",                  cat: "Pwn",        diff: "insane",  flags: 1, pts: 1000, desc: "Pirate crew roster manager with heap memory bugs" },
    // REVERSING
    { name: "Legends Gate",            cat: "Reversing",  diff: "medium",  flags: 1, pts: 300,  desc: "Protected VIP stadium gate binary" },
    { name: "Tournament Bracket",      cat: "Reversing",  diff: "insane",  flags: 3, pts: 1000, desc: "Three-stage tournament progression binary" },
    { name: "VAR Mobile Companion",    cat: "Reversing",  diff: "insane",  flags: 5, pts: 1500, desc: "Android mobile companion app with layered secrets" },
    // CRYPTO
    { name: "Coach Formation",         cat: "Crypto",     diff: "vhard",   flags: 1, pts: 750,  desc: "Custom cipher with known-plaintext pairs" },
    { name: "Cipher Championship",     cat: "Crypto",     diff: "insane",  flags: 3, pts: 1200, desc: "Three-round progressive cryptography championship" },
    { name: "VAR Override",            cat: "Crypto",     diff: "insane",  flags: 1, pts: 1000, desc: "ECDSA signature verification system with encrypted flag" },
    // MISC
    { name: "Coach GPT Jailbreak",     cat: "Misc",       diff: "medium",  flags: 2, pts: 350,  desc: "AI coaching assistant with hardened output filters" },
    { name: "Referee Briefing",        cat: "Misc",       diff: "hard",    flags: 2, pts: 500,  desc: "MCP-powered referee briefing tool server" },
    { name: "Ait Baha Nuclear",        cat: "Misc",       diff: "medium",  flags: 3, pts: 400,  desc: "Nuclear facility HMI with industrial control system" },
    { name: "Agadir Medport",          cat: "Misc",       diff: "medium",  flags: 3, pts: 400,  desc: "Maritime port IoT messaging broker" },
    // FORENSICS
    { name: "Malware Lab Stadium",     cat: "Forensics",  diff: "medium",  flags: 1, pts: 300,  desc: "Malware sample analysis lab — 10 questions, 70% pass" },
    { name: "Stadium IR",              cat: "Forensics",  diff: "hard",    flags: 2, pts: 550,  desc: "Compromised server incident response via SSH" },
    { name: "Stadium SOC",             cat: "Forensics",  diff: "medium",  flags: 1, pts: 300,  desc: "SOC analyst triage across 7 evidence files — 40 questions" },
    { name: "The VIP Invitation",      cat: "Forensics",  diff: "hard",    flags: 1, pts: 400,  desc: "Stadium invitation image with hidden data" },
    { name: "Pearl Binary Signature",  cat: "Forensics",  diff: "hard",    flags: 1, pts: 400,  desc: "Image mosaic encoding a binary signature" },
    // OSINT
    { name: "KDB Scouting Report",     cat: "OSINT",      diff: "insane",  flags: 4, pts: 1200, desc: "Multi-layer image with hidden intelligence" },
    { name: "Venue Recon",             cat: "OSINT",      diff: "medium",  flags: 1, pts: 300,  desc: "Identify a location from an image and its metadata" },
];

const DIFF_LABEL = {
    easy: "EASY", medium: "MEDIUM", hard: "HARD", vhard: "VERY HARD", insane: "INSANE"
};

// ═══ INTRO ══════════════════════════════════════════════════════
const intro = document.getElementById("intro");
const video = document.getElementById("introVideo");
const skipBtn = document.getElementById("skipBtn");
const countdown = document.getElementById("countdown");

function endIntro() {
    intro.style.transition = "opacity .7s ease, filter .7s ease";
    intro.style.opacity = "0";
    intro.style.filter = "blur(20px)";
    setTimeout(() => {
        intro.remove();
        document.getElementById("app").classList.remove("hidden");
        initApp();
    }, 700);
}

// Only advance on ENTER click — intro stays up forever otherwise
skipBtn.addEventListener("click", endIntro);

// Hide the unused countdown element
if (countdown) countdown.style.display = "none";

// Video: loop so it never stops
video.addEventListener("ended", () => { video.currentTime = 0; video.play(); });
video.loop = true;

// ═══ MAIN APP ═══════════════════════════════════════════════════
function initApp() {
    renderGrid(CHALLENGES);
    setupCatFilter();
    setupCardTilt();
    setupParticles();
}

function renderGrid(list) {
    const grid = document.getElementById("grid");
    grid.innerHTML = list.map((c, i) => `
        <article class="card" data-cat="${c.cat}" style="animation: fadeIn .6s cubic-bezier(0.2, 0.8, 0.2, 1) ${i * 0.03}s backwards">
            <div class="card-head">
                <div class="card-cat">${c.cat}</div>
                <div class="card-diff diff-${c.diff}">${DIFF_LABEL[c.diff]}</div>
            </div>
            <div class="card-title">${c.name}</div>
            <div class="card-desc">${c.desc}</div>
            <div class="card-foot">
                <div class="card-points">${c.pts} PTS</div>
                <div class="card-flags">${c.flags} FLAG${c.flags > 1 ? "S" : ""}</div>
            </div>
        </article>
    `).join("");
}

function setupCatFilter() {
    document.querySelectorAll(".cat").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".cat").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            const cat = btn.dataset.cat;
            const list = cat === "all" ? CHALLENGES : CHALLENGES.filter(c => c.cat === cat);
            renderGrid(list);
            setupCardTilt();
        });
    });
}

function setupCardTilt() {
    document.querySelectorAll(".card").forEach(card => {
        card.addEventListener("mousemove", (e) => {
            const r = card.getBoundingClientRect();
            const x = e.clientX - r.left;
            const y = e.clientY - r.top;
            const rx = ((y / r.height) - 0.5) * -6;
            const ry = ((x / r.width) - 0.5) * 6;
            card.style.transform = `translateY(-4px) perspective(1000px) rotateX(${rx}deg) rotateY(${ry}deg)`;
            card.style.setProperty("--mx", `${(x / r.width) * 100}%`);
            card.style.setProperty("--my", `${(y / r.height) * 100}%`);
        });
        card.addEventListener("mouseleave", () => {
            card.style.transform = "";
        });
    });
}

// ═══ PARTICLES (subtle floating dots) ═══════════════════════════
function setupParticles() {
    const canvas = document.getElementById("particles");
    const ctx = canvas.getContext("2d");
    let w, h, particles = [];

    function resize() {
        w = canvas.width = window.innerWidth;
        h = canvas.height = window.innerHeight;
    }
    resize();
    window.addEventListener("resize", resize);

    const COUNT = 60;
    for (let i = 0; i < COUNT; i++) {
        particles.push({
            x: Math.random() * w,
            y: Math.random() * h,
            vx: (Math.random() - 0.5) * 0.3,
            vy: (Math.random() - 0.5) * 0.3,
            r: Math.random() * 1.8 + 0.3,
            a: Math.random() * 0.6 + 0.2
        });
    }

    function tick() {
        ctx.clearRect(0, 0, w, h);

        // Connect nearby particles
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const p1 = particles[i], p2 = particles[j];
                const d = Math.hypot(p1.x - p2.x, p1.y - p2.y);
                if (d < 140) {
                    ctx.strokeStyle = `rgba(90,140,255,${0.12 * (1 - d / 140)})`;
                    ctx.lineWidth = 0.5;
                    ctx.beginPath();
                    ctx.moveTo(p1.x, p1.y);
                    ctx.lineTo(p2.x, p2.y);
                    ctx.stroke();
                }
            }
        }

        particles.forEach(p => {
            p.x += p.vx;
            p.y += p.vy;
            if (p.x < 0 || p.x > w) p.vx *= -1;
            if (p.y < 0 || p.y > h) p.vy *= -1;
            ctx.fillStyle = `rgba(90,140,255,${p.a})`;
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fill();
        });

        requestAnimationFrame(tick);
    }
    tick();
}
