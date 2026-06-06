const fs = require('fs');
const path = require('path');

const indexHtmlPath = path.join(__dirname, 'public', 'index.html');
let html = fs.readFileSync(indexHtmlPath, 'utf8');

// 1. Add Toast HTML and Script before </body>
const toastUI = `
    <!-- PREMIUM TOAST & MODAL OVERRIDES -->
    <div id="premium-toast-container"></div>
    
    <div id="premium-confirm-modal" class="premium-modal-overlay">
        <div class="premium-modal-content">
            <h3 id="premium-confirm-title">Confirm</h3>
            <p id="premium-confirm-message"></p>
            <div class="premium-modal-actions">
                <button id="premium-confirm-cancel" class="premium-btn secondary">Cancel</button>
                <button id="premium-confirm-ok" class="premium-btn primary">Confirm</button>
            </div>
        </div>
    </div>

    <div id="premium-prompt-modal" class="premium-modal-overlay">
        <div class="premium-modal-content">
            <h3 id="premium-prompt-title">Entering Info</h3>
            <p id="premium-prompt-message"></p>
            <input type="text" id="premium-prompt-input" class="premium-input" />
            <div class="premium-modal-actions">
                <button id="premium-prompt-cancel" class="premium-btn secondary">Cancel</button>
                <button id="premium-prompt-ok" class="premium-btn primary">Submit</button>
            </div>
        </div>
    </div>

    <style>
        /* PREMIUM SCROLLBARS */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        ::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.1);
            border-radius: 10px;
        }
        ::-webkit-scrollbar-thumb {
            background: rgba(59, 130, 246, 0.4);
            border-radius: 10px;
            border: 2px solid transparent;
            background-clip: padding-box;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: rgba(59, 130, 246, 0.8);
            border: 2px solid transparent;
            background-clip: padding-box;
        }
        .light-mode ::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.05);
        }
        .light-mode ::-webkit-scrollbar-thumb {
            background: rgba(59, 130, 246, 0.3);
            border: 2px solid transparent;
            background-clip: padding-box;
        }
        .light-mode ::-webkit-scrollbar-thumb:hover {
            background: rgba(59, 130, 246, 0.6);
        }

        /* MODAL FIX: Set max height and scrolling */
        #settings-modal .modal-content,
        #auth-modal .modal-content,
        #mfa-setup-modal .modal-content,
        #qr-modal .modal-content,
        .modal-content {
            max-height: 90vh;
            overflow-y: auto;
            max-width: 90vw;
        }

        /* LIGHT MODE FIX: Clean white sidebar */
        .light-mode #sidebar {
            background: #ffffff !important;
            border-right: 1px solid #e2e8f0;
            box-shadow: none !important;
        }
        .light-mode .modal-content {
            background: #ffffff !important;
            color: #1e293b;
        }

        /* PREMIUM BUTTON STYLES */
        button, .premium-btn {
            transition: all 0.2s ease-in-out;
        }
        .premium-btn.primary {
            background: linear-gradient(135deg, #2563eb, #1d4ed8);
            border: 1px solid rgba(59, 130, 246, 0.5);
            color: white;
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
        }
        .premium-btn.primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(59, 130, 246, 0.5);
        }
        .premium-btn.secondary {
            background: rgba(255, 255, 255, 0.1);
            color: white;
            border: 1px solid rgba(255, 255, 255, 0.2);
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
        }
        .premium-btn.secondary:hover {
            background: rgba(255, 255, 255, 0.2);
        }

        /* PREMIUM TOAST & Custom Modals */
        #premium-toast-container {
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 10000;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .premium-toast {
            background: rgba(15, 23, 42, 0.9);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(59, 130, 246, 0.3);
            color: white;
            padding: 12px 20px;
            border-radius: 10px;
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.5);
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 10px;
            animation: slideInUp 0.3s ease-out forwards;
        }
        .premium-toast.error {
            border-color: rgba(239, 68, 68, 0.5);
        }
        .premium-toast.success {
            border-color: rgba(16, 185, 129, 0.5);
        }
        @keyframes slideInUp {
            from { transform: translateY(100%); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        .premium-modal-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.6);
            backdrop-filter: blur(8px);
            display: none;
            justify-content: center;
            align-items: center;
            z-index: 20000;
        }
        .premium-modal-overlay.active {
            display: flex;
        }
        .premium-modal-content {
            background: #0f172a;
            border: 1px solid rgba(59, 130, 246, 0.2);
            padding: 24px;
            border-radius: 16px;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 20px 50px rgba(0,0,0,0.5);
            color: white;
            text-align: center;
        }
        .premium-modal-content h3 { margin-top: 0; color: #f8fafc; }
        .premium-modal-content p { color: #94a3b8; font-size: 14px; margin-bottom: 20px; }
        .premium-input {
            width: 100%;
            background: rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.1);
            color: white;
            padding: 10px;
            border-radius: 8px;
            margin-bottom: 20px;
            outline: none;
        }
        .premium-input:focus { border-color: #3b82f6; }
        .premium-modal-actions {
            display: flex;
            justify-content: center;
            gap: 12px;
        }
        
        .light-mode .premium-modal-content {
            background: #ffffff;
            color: #1e293b;
            border-color: #e2e8f0;
        }
        .light-mode .premium-modal-content h3 { color: #0f172a; }
        .light-mode .premium-modal-content p { color: #64748b; }
        .light-mode .premium-btn.secondary {
            background: #f1f5f9;
            color: #1e293b;
            border-color: #cbd5e1;
        }
        .light-mode .premium-input {
            background: #f8fafc;
            color: #0f172a;
        }
    </style>

    <script>
        function showPremiumToast(text, type='info') {
            const container = document.getElementById('premium-toast-container');
            const toast = document.createElement('div');
            toast.className = 'premium-toast ' + type;
            let icon = 'ℹ️';
            if(type === 'success') icon = '✅';
            if(type === 'error') icon = '⚠️';
            toast.innerHTML = \`<span>\${icon}</span> <span>\${text}</span>\`;
            container.appendChild(toast);
            setTimeout(() => {
                toast.style.opacity = '0';
                toast.style.transform = 'translateY(20px)';
                toast.style.transition = 'all 0.3s ease';
                setTimeout(() => toast.remove(), 300);
            }, 3000);
        }

        window.alert = function(msg) {
            showPremiumToast(msg, msg && msg.toLowerCase && (msg.toLowerCase().includes('error') || msg.toLowerCase().includes('failed') || msg.toLowerCase().includes('denied')) ? 'error' : 'success');
        };

        window.premiumConfirm = function(message) {
            return new Promise((resolve) => {
                const overlay = document.getElementById('premium-confirm-modal');
                const messageEl = document.getElementById('premium-confirm-message');
                const btnOk = document.getElementById('premium-confirm-ok');
                const btnCancel = document.getElementById('premium-confirm-cancel');
                
                messageEl.textContent = message;
                overlay.classList.add('active');
                
                const cleanup = () => {
                    overlay.classList.remove('active');
                    btnOk.removeEventListener('click', onOk);
                    btnCancel.removeEventListener('click', onCancel);
                };
                const onOk = () => { cleanup(); resolve(true); };
                const onCancel = () => { cleanup(); resolve(false); };
                
                btnOk.addEventListener('click', onOk);
                btnCancel.addEventListener('click', onCancel);
            });
        };

        window.premiumPrompt = function(message, defaultVal='') {
            return new Promise((resolve) => {
                const overlay = document.getElementById('premium-prompt-modal');
                const messageEl = document.getElementById('premium-prompt-message');
                const inputEl = document.getElementById('premium-prompt-input');
                const btnOk = document.getElementById('premium-prompt-ok');
                const btnCancel = document.getElementById('premium-prompt-cancel');
                
                messageEl.textContent = message;
                inputEl.value = defaultVal || '';
                overlay.classList.add('active');
                inputEl.focus();
                
                const cleanup = () => {
                    overlay.classList.remove('active');
                    btnOk.removeEventListener('click', onOk);
                    btnCancel.removeEventListener('click', onCancel);
                };
                const onOk = () => { cleanup(); resolve(inputEl.value); };
                const onCancel = () => { cleanup(); resolve(null); };
                
                btnOk.addEventListener('click', onOk);
                btnCancel.addEventListener('click', onCancel);
            });
        };
    </script>
</body>`;

html = html.replace('</body>', toastUI);

// Replace confirm/prompt usages to await window.premiumConfirm / premiumPrompt

// 1. Session Revoke
html = html.replace("if (!confirm('Are you sure you want to revoke this session?')) return;", "if (!(await window.premiumConfirm('Are you sure you want to revoke this session?'))) return;");

// 2. Session Revoke All
html = html.replace("if (!confirm('Logout all other devices?')) return;", "if (!(await window.premiumConfirm('Logout all other devices?'))) return;");

// 3. User block/unblock (admin) Let's assume it's sync, wait, onclick handler can be async? The admin button clicked. It might be sync. We need to wrap it if it's sync. "const confirmation = confirm..."
html = html.replace("const confirmation = confirm(`Are you sure you want to ${target.textContent.toLowerCase()} this user?`);", "const confirmation = await window.premiumConfirm(`Are you sure you want to ${target.textContent.toLowerCase()} this user?`);");

// 4. Delete coupon
html = html.replace("if (!confirm('Delete coupon?')) return;", "if (!(await window.premiumConfirm('Delete coupon?'))) return;");

// 5. Delete Chat:
html = html.replace("if (confirm('Are you sure you want to delete this chat?')) {", "if (await window.premiumConfirm('Are you sure you want to delete this chat?')) {");

// 6. Disable MFA Prompt
html = html.replace("const token = prompt('Enter code from your app to disable MFA:');", "const token = await window.premiumPrompt('Enter code from your app to disable MFA:');");

// 7. Chat Title Rename
html = html.replace('const newTitle = prompt("Enter new chat title:", chat.title);', 'const newTitle = await window.premiumPrompt("Enter new chat title:", chat.title);');


// Upgrade QR Code / MFA Experience
// Find QR modal content and replace.
const mfaOverlayIndex = html.indexOf('<div class="modal" id="qr-modal"');
if(mfaOverlayIndex > -1){
    // Replace inline styles for qr to make it glowing
    html = html.replace('id="qr-image" style="width:200px; height:200px; border-radius:10px; border:2px solid var(--blue-dark-border-color); padding:10px; background:white; margin-top:20px;"', 'id="qr-image" style="width:200px; height:200px; border-radius:15px; border:2px solid rgba(59,130,246,0.5); padding:10px; background:white; margin: 20px auto; box-shadow: 0 0 30px rgba(59,130,246,0.4);"');
    html = html.replace('<button onclick="completeMfaSetup()">Complete Setup</button>', '<button onclick="completeMfaSetup()" class="premium-btn primary">Complete Setup</button>');
}

fs.writeFileSync(indexHtmlPath, html, 'utf8');

const indexCssPath = path.join(__dirname, 'public', 'index.css');
let css = fs.readFileSync(indexCssPath, 'utf8');

const premiumButtonsCss = `
/* ADDITIONAL PREMIUM STYLES FOR EXISTING CLASSES */
.save-btn, .auth-btn, .admin-btn, .landing-btn-primary, .plan-btn.cta, .edit-save-btn {
    background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%) !important;
    color: white !important;
    border: 1px solid rgba(59, 130, 246, 0.4) !important;
    border-radius: 10px !important;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
    box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3) !important;
    backdrop-filter: blur(5px);
}
.save-btn:hover, .auth-btn:hover, .admin-btn:hover, .landing-btn-primary:hover, .plan-btn.cta:hover, .edit-save-btn:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 6px 20px rgba(59, 130, 246, 0.5) !important;
    border-color: rgba(59, 130, 246, 0.6) !important;
}

.cancel-btn, .edit-cancel-btn {
    background: rgba(255, 255, 255, 0.05) !important;
    color: #94a3b8 !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
    border-radius: 10px !important;
    transition: all 0.3s ease !important;
}
.cancel-btn:hover, .edit-cancel-btn:hover {
    background: rgba(255, 255, 255, 0.1) !important;
    color: #f8fafc !important;
    transform: translateY(-2px) !important;
}
.light-mode .cancel-btn, .light-mode .edit-cancel-btn {
    background: #f1f5f9 !important;
    color: #1e293b !important;
    border-color: #cbd5e1 !important;
}
`;
if(!css.includes('/* ADDITIONAL PREMIUM STYLES FOR EXISTING CLASSES */')) {
    fs.writeFileSync(indexCssPath, css + premiumButtonsCss, 'utf8');
}