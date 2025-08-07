// Dynamic events for Finite State Third Party Import Recorder
function toggleVersionField() {
    var externalizableIdCheckbox = document.getElementById('thirdExternalizableId');
    var versionDiv = document.getElementById('thirdVersion');
    
    if (externalizableIdCheckbox && versionDiv) {
        if (externalizableIdCheckbox.checked) {
            versionDiv.style.display = 'none';
        } else {
            versionDiv.style.display = 'block';
        }
    }
}

document.addEventListener('DOMContentLoaded', function() {
    toggleVersionField();
    
    // Add event listener to checkbox
    var externalizableIdCheckbox = document.getElementById('thirdExternalizableId');
    if (externalizableIdCheckbox) {
        externalizableIdCheckbox.addEventListener('change', toggleVersionField);
    }
});

(function() {
    // your page initialization code here
    // the DOM will be available here
    
    toggleVersionField();
})();

// Detect when your plugin is added as a post-build action
Behaviour.specify(".finite-state-third-party-import", 'my-plugin', 100, function (element) {
    // Trigger a custom event when your plugin's fields are loaded
    var externalizableIdCheckbox = document.getElementById("thirdExternalizableId");
    if (externalizableIdCheckbox) {
        externalizableIdCheckbox.addEventListener("click", toggleVersionField);
    }
}); 