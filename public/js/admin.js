// Standalone Admin Panel Script for RiserGPT (Does not load Firebase Auth)

(function() {
    const ADMIN_SESSION_KEY = 'risergpt_isAdminLoggedIn';
    let globalConfig = { announcement: {}, coupons: [], plans: [] };
    let currentEditingPlanId = null;

    // DOM Elements
    const adminLoginScreen = document.getElementById('admin-login-screen');
    const adminPanel = document.getElementById('admin-panel');
    const adminLoginForm = document.getElementById('admin-login-form');
    const adminErrorMessage = document.getElementById('admin-error-message');
    const adminLogoutBtn = document.getElementById('admin-logout-btn');
    const adminRefreshBtn = document.getElementById('admin-refresh-btn');
    const userTableBody = document.getElementById('user-table-body');
    const userSearchInput = document.getElementById('user-search-input');
    const adminTabs = document.querySelectorAll('.admin-tab-btn');
    
    // Stats elements
    const statsTotalUsers = document.getElementById('stats-total-users');
    const statsActiveUsers = document.getElementById('stats-active-users');
    const statsBannedUsers = document.getElementById('stats-banned-users');
    const statsPlanDist = document.getElementById('stats-plan-dist');

    // Admin Config Elements
    const adminAnnouncementText = document.getElementById('admin-announcement-text');
    const adminAnnouncementStatus = document.getElementById('admin-announcement-status');
    const saveAnnouncementBtn = document.getElementById('save-announcement-btn');
    const newCouponCode = document.getElementById('new-coupon-code');
    const newCouponType = document.getElementById('new-coupon-type');
    const newCouponValue = document.getElementById('new-coupon-value');
    const addCouponBtn = document.getElementById('add-coupon-btn');
    const couponsTableBody = document.getElementById('coupons-table-body');
    
    // Admin Plans Config Elements
    const plansTableBody = document.getElementById('plans-table-body');
    const editPlanModal = document.getElementById('edit-plan-modal');
    const modalPlanNameDisplay = document.getElementById('modal-plan-name-display');
    const modalPlanName = document.getElementById('modal-plan-name');
    const modalPlanPrice = document.getElementById('modal-plan-price');
    const modalPlanDiscount = document.getElementById('modal-plan-discount');
    const modalPlanDesc = document.getElementById('modal-plan-desc');
    const modalPlanFeatures = document.getElementById('modal-plan-features');
    const planSaveBtn = document.getElementById('plan-save-btn');
    const planCancelBtn = document.getElementById('plan-cancel-btn');

    // User Edit Modal Elements
    const editUserModal = document.getElementById('edit-user-modal');
    const modalUserName = document.getElementById('modal-user-name');
    const modalUserEmail = document.getElementById('modal-user-email');
    const modalUserPlan = document.getElementById('modal-user-plan');
    const modalUserPassword = document.getElementById('modal-user-password');
    const modalCancelBtn = document.getElementById('modal-cancel-btn');
    const modalSaveBtn = document.getElementById('modal-save-btn');

    // --- SECURITY INJECTION: JWT Fetch Interceptor ---
    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
        let [resource, config] = args;
        if (typeof resource === 'string' && resource.startsWith('/api/')) {
            config = config || {};
            config.headers = config.headers || {};
            const token = localStorage.getItem('authToken');
            if (token) {
                if (config.headers instanceof Headers) {
                    config.headers.append('Authorization', `Bearer ${token}`);
                } else {
                    config.headers['Authorization'] = `Bearer ${token}`;
                }
            }
            args[1] = config;
        }
        
        const response = await originalFetch.apply(this, args);
        
        if (response.status === 401 || response.status === 403) {
            const clone = response.clone();
            try {
                const data = await clone.json();
                if (data.sessionRevoked) {
                    alert(data.error || 'Your session was terminated.');
                    handleAdminLogout();
                }
            } catch(e) {}
        }
        
        return response;
    };

    // --- TOASTS & MODALS ---
    function showPremiumToast(text, type='info') {
        const container = document.getElementById('premium-toast-container');
        if (!container) return;
        const toast = document.createElement('div');
        toast.className = 'premium-toast ' + type;
        let icon = 'ℹ️';
        if(type === 'success') icon = '✅';
        if(type === 'error') icon = '⚠️';
        toast.innerHTML = `<span>${icon}</span> <span>${text}</span>`;
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

    function setButtonLoading(form, isLoading) {
        const button = form.querySelector('.auth-btn');
        if (!button) return;
        const text = button.querySelector('.btn-text');
        const spinner = button.querySelector('.btn-spinner');
        button.disabled = isLoading;
        if (text) text.classList.toggle('hidden', isLoading);
        if (spinner) spinner.classList.toggle('hidden', !isLoading);
    }

    function setAuthError(message) {
        if (!adminErrorMessage) return;
        if (message) {
            adminErrorMessage.textContent = message;
            adminErrorMessage.style.display = 'block';
        } else {
            adminErrorMessage.style.display = 'none';
        }
    }

    function getPlanClass(planName) {
        switch (planName) {
            case 'Muft Plan': return 'plan-muft';
            case 'Prarambh Plan': return 'plan-prarambh';
            case 'Tiranga Plan': return 'plan-tiranga';
            case 'Bharat Plan': return 'plan-bharat';
            default: return 'plan-muft';
        }
    }

    // --- API OPERATIONS ---
    async function fetchUsers() {
        try {
            console.log("[Admin] Fetching users from /api/users...");
            const response = await fetch('/api/users');
            if (!response.ok) {
                const textBody = await response.text();
                throw new Error(`Failed to fetch users (Status: ${response.status}) Body: ${textBody}`);
            }
            const users = await response.json();
            return users;
        } catch (error) {
            console.error("Fetch Users Error:", error);
            showPremiumToast("Failed to fetch users.", "error");
            return [];
        }
    }

    async function saveUsers(users) {
        try {
            const response = await fetch('/api/users/save-bulk', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(users)
            });
            if (!response.ok) throw new Error('Failed to save users');
        } catch (error) {
            console.error("Save Users Error:", error);
            throw error;
        }
    }

    async function fetchLocalConfig() {
        try {
            const response = await fetch('/api/config', { cache: 'no-cache' });
            if (!response.ok) return { announcement: {}, coupons: [], plans: [] };
            return await response.json();
        } catch (e) {
            console.error("Config Fetch Error:", e);
            return { announcement: {}, coupons: [], plans: [] };
        }
    }

    async function saveLocalConfig(config) {
        try {
            const response = await fetch('/api/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            });
            if (!response.ok) throw new Error("Failed to save config on server");
            globalConfig = config;
        } catch (e) {
            console.error("Save Config Error:", e);
            throw e;
        }
    }

    // --- VIEWS ROUTING ---
    function showAdminLogin() {
        adminPanel.style.display = 'none';
        adminLoginScreen.style.display = 'flex';
        setAuthError('');
    }

    function showAdminPanel() {
        adminLoginScreen.style.display = 'none';
        adminPanel.style.display = 'flex';
        initAdminPanel();
    }

    // --- ACTION HANDLERS ---
    async function handleAdminLogin(e) {
        e.preventDefault();
        setButtonLoading(adminLoginForm, true);
        setAuthError('');
        const username = document.getElementById('admin-username').value;
        const password = document.getElementById('admin-password').value;

        try {
            let bodyData = { username, password };
            let response = await window.fetch('/api/users/admin-login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(bodyData)
            });
            let data = await response.json();

            while (response.status === 403 && data.requiresCaptcha) {
                const answer = await window.premiumPrompt(data.mathQuestion || 'Verification Required');
                if (answer === null) {
                    setAuthError('Captcha cancelled.');
                    setButtonLoading(adminLoginForm, false);
                    return;
                }
                bodyData.captchaAnswer = answer;
                response = await window.fetch('/api/users/admin-login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(bodyData)
                });
                data = await response.json();
            }

            if (response.ok && data.success) {
                localStorage.setItem('authToken', data.token);
                sessionStorage.setItem(ADMIN_SESSION_KEY, 'true');
                showAdminPanel();
            } else {
                setAuthError(data.error || 'Invalid admin credentials.');
            }
        } catch (err) {
            setAuthError('Service temporarily unavailable');
        }
        setButtonLoading(adminLoginForm, false);
    }

    function handleAdminLogout() {
        sessionStorage.removeItem(ADMIN_SESSION_KEY);
        // Clean out authToken to be safe
        localStorage.removeItem('authToken');
        showAdminLogin();
    }

    async function initAdminPanel() {
        try {
            const [users, config] = await Promise.all([fetchUsers(), fetchLocalConfig()]);
            globalConfig = config;
            renderStats(users);
            renderUserTable(users);
            loadAdminConfig(config);
            renderPlansTable(config.plans || []);
        } catch (error) {
            alert(`Error loading admin data: ${error.message}`);
        }
    }

    function loadAdminConfig(config) {
        if (config.announcement) {
            adminAnnouncementText.value = config.announcement.text || '';
            adminAnnouncementStatus.value = config.announcement.status || 'inactive';
        }
        renderCouponsTable(config.coupons || []);
    }

    function renderStats(users) {
        const total = users.length;
        const banned = users.filter(u => u.isBanned).length;
        const active = total - banned;
        
        const planCounts = users.reduce((acc, user) => {
            const plan = user.plan || 'Muft Plan';
            acc[plan] = (acc[plan] || 0) + 1;
            return acc;
        }, {});
        
        statsTotalUsers.textContent = total;
        statsActiveUsers.textContent = active;
        statsBannedUsers.textContent = banned;

        statsPlanDist.innerHTML = Object.entries(planCounts).map(([plan, count]) => {
            const planClass = getPlanClass(plan);
            return `<span class="plan-badge ${planClass}" title="${plan}">${count}</span>`;
        }).join('');
    }

    function renderUserTable(users) {
        userTableBody.innerHTML = '';
        if (users.length === 0) {
            userTableBody.innerHTML = '<tr><td colspan="6" style="text-align: center;">No users found.</td></tr>';
            return;
        }
        users.forEach(user => {
            const plan = user.plan || 'Muft Plan';
            const planClass = getPlanClass(plan);
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>#${user.id || 'N/A'}</td>
                <td>${user.name}</td>
                <td>${user.email}</td>
                <td><span class="plan-badge ${planClass}">${plan}</span></td>
                <td>${user.isBanned ? 'Banned' : 'Active'}</td>
                <td class="actions-cell">
                    <button class="edit-btn" data-email="${user.email}">Edit</button>
                    <button class="ban-btn ${user.isBanned ? 'banned' : ''}" data-email="${user.email}">${user.isBanned ? 'Unban' : 'Ban'}</button>
                </td>
            `;
            userTableBody.appendChild(row);
        });
    }

    function filterUsers() {
        const searchTerm = userSearchInput.value.toLowerCase();
        const rows = userTableBody.querySelectorAll('tr');
        rows.forEach(row => {
            const id = row.cells[0].textContent.toLowerCase();
            const name = row.cells[1].textContent.toLowerCase();
            const email = row.cells[2].textContent.toLowerCase();
            if (id.includes(searchTerm) || name.includes(searchTerm) || email.includes(searchTerm)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }

    async function handleAdminTableClick(e) {
        const target = e.target;
        const email = target.dataset.email;
        if (!email) return;

        if (target.classList.contains('edit-btn')) {
            const users = await fetchUsers();
            const user = users.find(u => u.email === email);
            openEditModal(user);
        } else if (target.classList.contains('ban-btn')) {
            const confirmation = await window.premiumConfirm(`Are you sure you want to ${target.textContent.toLowerCase()} this user?`);
            if (confirmation) {
                try {
                    const users = await fetchUsers();
                    const userIndex = users.findIndex(u => u.email === email);
                    users[userIndex].isBanned = !users[userIndex].isBanned;
                    await saveUsers(users);
                    initAdminPanel();
                } catch(error) {
                    alert('Failed to update user status.');
                }
            }
        }
    }

    function openEditModal(user) {
        modalUserName.textContent = user.name;
        modalUserEmail.value = user.email;
        modalUserPlan.value = user.plan || 'Muft Plan';
        const expirySelect = document.getElementById('modal-user-plan-expiry');
        if (expirySelect) expirySelect.value = user.planExpiry || 'forever';
        modalUserPassword.value = '';
        editUserModal.style.display = 'flex';
    }

    function closeEditModal() {
        editUserModal.style.display = 'none';
    }

    async function handleSaveChanges() {
        const email = modalUserEmail.value;
        const newPassword = modalUserPassword.value.trim();
        const newPlan = modalUserPlan.value;
        const expirySelect = document.getElementById('modal-user-plan-expiry');
        const newExpiry = expirySelect ? expirySelect.value : 'forever';

        try {
            const users = await fetchUsers();
            const userIndex = users.findIndex(u => u.email === email);
            if (userIndex > -1) {
                if (newPassword) {
                    users[userIndex].password = newPassword;
                }
                users[userIndex].plan = newPlan;
                users[userIndex].planExpiry = newExpiry;
                
                if (newExpiry !== 'forever') {
                    const expiryDate = new Date();
                    expiryDate.setDate(expiryDate.getDate() + parseInt(newExpiry));
                    users[userIndex].expiryDate = expiryDate.toISOString();
                } else {
                    delete users[userIndex].expiryDate;
                }

                await saveUsers(users);
                alert('User details updated successfully!');
                closeEditModal();
                initAdminPanel();
            }
        } catch(error) {
            alert('Failed to save changes.');
        }
    }
    
    // --- ADMIN PLAN MANAGEMENT ---
    function renderPlansTable(plans) {
        plansTableBody.innerHTML = plans.map((p, index) => `
            <tr>
                <td>${p.name} ${p.isHighlight ? '(Highlight)' : ''}</td>
                <td>₹${p.price}</td>
                <td>${p.discount ? '₹' + p.discount : '-'}</td>
                <td>${p.description}</td>
                <td class="actions-cell">
                    <button class="edit-plan-btn" data-index="${index}">Edit</button>
                </td>
            </tr>
        `).join('');
    }
    
    function handlePlanTableClick(e) {
        if(e.target.classList.contains('edit-plan-btn')) {
            const index = e.target.dataset.index;
            const plan = globalConfig.plans[index];
            currentEditingPlanId = index;
            
            modalPlanNameDisplay.textContent = plan.name;
            modalPlanName.value = plan.name;
            modalPlanPrice.value = plan.price;
            modalPlanDiscount.value = plan.discount || 0;
            modalPlanDesc.value = plan.description;
            modalPlanFeatures.value = plan.features.join('\n');
            
            editPlanModal.style.display = 'flex';
        }
    }
    
    async function handleSavePlan() {
        if(currentEditingPlanId === null) return;
        
        try {
            const plans = [...globalConfig.plans];
            plans[currentEditingPlanId] = {
                ...plans[currentEditingPlanId],
                name: modalPlanName.value,
                price: parseInt(modalPlanPrice.value),
                discount: parseInt(modalPlanDiscount.value),
                description: modalPlanDesc.value,
                features: modalPlanFeatures.value.split('\n').filter(l => l.trim().length > 0)
            };
            
            const newConfig = { ...globalConfig, plans };
            await saveLocalConfig(newConfig);
            
            renderPlansTable(newConfig.plans);
            editPlanModal.style.display = 'none';
            alert('Plan updated successfully!');
        } catch(e) { alert('Failed to update plan.'); }
    }
    
    // --- ADMIN CONFIG HANDLERS ---
    async function handleSaveAnnouncement() {
        try {
            const config = await fetchLocalConfig();
            config.announcement = {
                text: adminAnnouncementText.value,
                status: adminAnnouncementStatus.value
            };
            await saveLocalConfig(config);
            alert('Announcement updated!');
        } catch(e) { alert('Failed to save announcement.'); }
    }
    
    async function handleAddCoupon() {
        const code = newCouponCode.value.trim().toUpperCase();
        const type = newCouponType.value;
        const value = newCouponValue.value.trim(); 
        
        if (!code) return alert("Code required");
        
        try {
            const config = await fetchLocalConfig();
            if (!config.coupons) config.coupons = [];
            
            config.coupons.push({ code, type, value: value ? parseFloat(value) : 0 });
            await saveLocalConfig(config);
            
            newCouponCode.value = '';
            newCouponValue.value = '';
            renderCouponsTable(config.coupons);
        } catch(e) { alert('Failed to add coupon.'); }
    }
    
    function renderCouponsTable(coupons) {
        couponsTableBody.innerHTML = coupons.map((c, index) => `
            <tr>
                <td>${c.code}</td>
                <td>${c.type.startsWith('plan') ? c.type.replace('plan_', '').charAt(0).toUpperCase() + c.type.replace('plan_', '').slice(1) + ' Plan' : 'Discount'}</td>
                <td>${c.type.startsWith('plan') ? 'FREE' : c.value + '%'}</td>
                <td><button class="delete-coupon-btn" data-index="${index}" style="color: #e53e3e; background:none; border:none; cursor:pointer;">Delete</button></td>
            </tr>
        `).join('');
    }

    couponsTableBody.addEventListener('click', async (e) => {
        if (e.target.classList.contains('delete-coupon-btn')) {
            const index = e.target.dataset.index;
            if (!(await window.premiumConfirm('Delete coupon?'))) return;
            try {
                const config = await fetchLocalConfig();
                config.coupons.splice(index, 1);
                await saveLocalConfig(config);
                renderCouponsTable(config.coupons);
            } catch(e) { alert('Failed delete'); }
        }
    });

    // --- INITIAL BINDINGS & BOOT ---
    function init() {
        // Event Listeners
        adminLoginForm.addEventListener('submit', handleAdminLogin);
        adminLogoutBtn.addEventListener('click', handleAdminLogout);
        adminRefreshBtn.addEventListener('click', initAdminPanel);

        adminTabs.forEach(btn => {
            btn.addEventListener('click', () => {
                adminTabs.forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.admin-tab-content').forEach(c => c.classList.remove('active'));
                btn.classList.add('active');
                document.getElementById(`admin-tab-${btn.dataset.tab}`).classList.add('active');
            });
        });

        userSearchInput.addEventListener('input', filterUsers);
        userTableBody.addEventListener('click', handleAdminTableClick);
        modalCancelBtn.addEventListener('click', closeEditModal);
        modalSaveBtn.addEventListener('click', handleSaveChanges);
        saveAnnouncementBtn.addEventListener('click', handleSaveAnnouncement);
        addCouponBtn.addEventListener('click', handleAddCoupon);
        
        plansTableBody.addEventListener('click', handlePlanTableClick);
        planCancelBtn.addEventListener('click', () => editPlanModal.style.display = 'none');
        planSaveBtn.addEventListener('click', handleSavePlan);

        // Security shortcuts for admin
        document.addEventListener('contextmenu', e => e.preventDefault());
        document.onkeydown = function(e) {
            if (e.keyCode == 123) return false; // F12
            if (e.ctrlKey && e.shiftKey && (e.keyCode == 73 || e.keyCode == 74)) return false; // Ctrl+Shift+I/J
            if (e.ctrlKey && e.keyCode == 85) return false; // Ctrl+U
            if (e.ctrlKey && e.keyCode == 83) return false; // Ctrl+S
        };

        // Check Login State
        if (sessionStorage.getItem(ADMIN_SESSION_KEY) && localStorage.getItem('authToken')) {
            showAdminPanel();
        } else {
            showAdminLogin();
        }
    }

    // Load
    if (document.readyState === 'loading') {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();