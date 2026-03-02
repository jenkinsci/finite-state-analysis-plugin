// js
(function() {
  function updateContainerVisibility(checkbox, container) {
    if (!container) return;
    const  versionContainer = container.querySelector('.fs-version-container');
    if (!checkbox || !versionContainer) return;
    versionContainer.classList.toggle('jenkins-hidden', checkbox.checked);
  }

  function updateReachabilityState(scaCheckbox) {
    var container = scaCheckbox.closest('.finite-state-common');
    if (!container) return;
    var reachabilityCheckbox = container.querySelector('.fs-reachabilityEnabled');
    if (!reachabilityCheckbox) return;

    if (!scaCheckbox.checked) {
      reachabilityCheckbox.checked = false;
      reachabilityCheckbox.disabled = true;
    } else {
      reachabilityCheckbox.disabled = false;
    }
  }

  Behaviour.specify('.fs-externalizableId', 'finite-state-common', 0, function(checkbox) {
    const container = checkbox.closest('.finite-state-common');
    updateContainerVisibility(checkbox, container);
    checkbox.addEventListener('click', function() {
      updateContainerVisibility(checkbox, container);
    });
  });

  Behaviour.specify('.fs-scaEnabled', 'finite-state-common', 0, function(checkbox) {
    updateReachabilityState(checkbox);
    checkbox.addEventListener('click', function() {
      updateReachabilityState(checkbox);
    });
  });
})();