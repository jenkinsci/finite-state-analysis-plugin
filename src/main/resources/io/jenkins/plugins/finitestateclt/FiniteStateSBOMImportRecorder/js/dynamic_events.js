// Dynamic events for Finite State SBOM Import Recorder
(function() {
    'use strict';
    
    // Show/hide version field based on externalizableId checkbox
    function toggleVersionField() {
        var externalizableIdCheckbox = document.getElementById('externalizableId');
        var versionDiv = document.getElementById('version');
        
        if (externalizableIdCheckbox && versionDiv) {
            if (externalizableIdCheckbox.checked) {
                versionDiv.style.display = 'none';
            } else {
                versionDiv.style.display = 'block';
            }
        }
    }
    
    // Initialize on page load
    document.addEventListener('DOMContentLoaded', function() {
        toggleVersionField();
        
        // Add event listener to checkbox
        var externalizableIdCheckbox = document.getElementById('externalizableId');
        if (externalizableIdCheckbox) {
            externalizableIdCheckbox.addEventListener('change', toggleVersionField);
        }
    });
})();