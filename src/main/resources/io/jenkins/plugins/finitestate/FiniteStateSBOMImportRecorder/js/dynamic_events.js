// Dynamic events for Finite State SBOM Import Recorder
function toggleSbomVersionField() {
    var externalizableIdCheckbox = document.getElementById('sbomExternalizableId');
    var versionDiv = document.getElementById('sbomVersion');
    if (externalizableIdCheckbox && versionDiv) {
        if (externalizableIdCheckbox.checked) {
            versionDiv.style.display = 'none';
        } else {
            versionDiv.style.display = 'block';
        }
    }
}

document.addEventListener('DOMContentLoaded', function() {
    toggleSbomVersionField();
    
    // Add event listener to checkbox
    var externalizableIdCheckbox = document.getElementById('sbomExternalizableId');
    if (externalizableIdCheckbox) {
        externalizableIdCheckbox.addEventListener('change', toggleSbomVersionField);
    }
});

(function() {
    // your page initialization code here
    // the DOM will be available here
    
    toggleSbomVersionField();
})();

// Detect when your plugin is added as a post-build action
Behaviour.specify(".finite-state-sbom-import", 'my-plugin', 200, function (element) {
    // Trigger a custom event when your plugin's fields are loaded
    var externalizableIdCheckbox = document.getElementById("sbomExternalizableId");
    if (externalizableIdCheckbox) {
        externalizableIdCheckbox.addEventListener("click", toggleSbomVersionField);
    }
}); 