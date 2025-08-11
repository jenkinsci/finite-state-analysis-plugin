(function() {
  function updateContainerVisibility(container) {
    if (!container) return;
    var checkbox = container.querySelector('input[type="checkbox"][name$="externalizableId"]');
    var versionContainer = container.querySelector('.fs-version-container');
    if (!checkbox || !versionContainer) return;
    versionContainer.style.display = checkbox.checked ? 'none' : '';
  }

  function initializeAll() {
    var containers = document.querySelectorAll('.finite-state-common');
    containers.forEach(updateContainerVisibility);
  }

  document.addEventListener('DOMContentLoaded', initializeAll);
  document.addEventListener('change', function(e) {
    var target = e && e.target;
    if (!target || target.type !== 'checkbox') return;
    if (!target.name || !target.name.endsWith('externalizableId')) return;
    var container = target.closest('.finite-state-common');
    updateContainerVisibility(container);
  });
})();


