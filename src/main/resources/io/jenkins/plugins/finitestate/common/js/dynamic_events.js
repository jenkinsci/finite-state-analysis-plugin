// js
(function() {
  function updateContainerVisibility(checkbox, container) {
    if (!container) return;
    const  versionContainer = container.querySelector('.fs-version-container');
    if (!checkbox || !versionContainer) return;
    versionContainer.classList.toggle('jenkins-hidden', checkbox.checked);
  }

  Behaviour.specify('.fs-externalizableId', 'finite-state-common', 0, function(checkbox) {
    const container = checkbox.closest('.finite-state-common');
    updateContainerVisibility(checkbox, container);
    checkbox.addEventListener('click', function() {
      updateContainerVisibility(checkbox, container);
    });
  });
})();