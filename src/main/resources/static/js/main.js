/**
 * ScamLens - Core JavaScript Client
 */

const ScamLens = {
    // Utility to determine badge class
    getRiskBadgeClass(level) {
        switch ((level || '').toLowerCase()) {
            case 'critical': return 'badge-risk-critical';
            case 'high': return 'badge-risk-high';
            case 'medium': return 'badge-risk-medium';
            case 'low': return 'badge-risk-low';
            default: return 'badge-risk-low';
        }
    },

    // Utility to get risk level color hex
    getRiskColor(level) {
        switch ((level || '').toLowerCase()) {
            case 'critical': return '#ef4444';
            case 'high': return '#f97316';
            case 'medium': return '#eab308';
            case 'low': return '#10b981';
            default: return '#10b981';
        }
    },

    // Character counter for textarea
    initCharCounter(textareaId, counterId, max = 10000) {
        const textarea = document.getElementById(textareaId);
        const counter = document.getElementById(counterId);
        if (!textarea || !counter) return;

        const update = () => {
            const len = textarea.value.length;
            counter.textContent = `${len.toLocaleString()} / ${max.toLocaleString()} chars`;
            if (len > max) {
                counter.classList.add('text-danger');
            } else {
                counter.classList.remove('text-danger');
            }
        };

        textarea.addEventListener('input', update);
        update();
    },

    // Show toast or alert notification
    showAlert(containerId, message, type = 'info') {
        const container = document.getElementById(containerId);
        if (!container) return;

        const icon = type === 'danger' ? 'fa-triangle-exclamation' :
                     type === 'success' ? 'fa-circle-check' : 'fa-circle-info';

        container.innerHTML = `
            <div class="alert alert-${type} alert-dismissible fade show cyber-card" role="alert">
                <i class="fa-solid ${icon} me-2"></i> ${message}
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        `;
    },

    // Copy text to clipboard
    copyToClipboard(text, triggerBtn) {
        navigator.clipboard.writeText(text).then(() => {
            const originalHtml = triggerBtn.innerHTML;
            triggerBtn.innerHTML = '<i class="fa-solid fa-check text-success"></i> Copied!';
            setTimeout(() => {
                triggerBtn.innerHTML = originalHtml;
            }, 2000);
        });
    }
};

window.ScamLens = ScamLens;
