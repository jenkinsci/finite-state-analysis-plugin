function toggleFields() {
    var versionField = document.getElementById("version");
    var externalizableIdCheckbox = document.getElementById("externalizableId");
    if (externalizableIdCheckbox){
        if (externalizableIdCheckbox.checked) {
            versionField.style.display = "none";
        } else {
            versionField.style.display = "block";
        }
    }
}

function initializeScanTypeCheckboxes() {
    // Ensure SCA is always enabled by default (it's required)
    var scaCheckbox = document.querySelector('input[name="scaEnabled"]');
    if (scaCheckbox) {
        scaCheckbox.checked = true;
    }
}

document.addEventListener("DOMContentLoaded", function() {
    toggleFields();
    initializeScanTypeCheckboxes();
});

(function() {
    // your page initialization code here
    // the DOM will be available here
    
    toggleFields();
    initializeScanTypeCheckboxes();
})();

// Detect when your plugin is added as a post-build action
Behaviour.specify(".finite-state-clt", 'my-plugin', 100, function (element) {
    // Trigger a custom event when your plugin's fields are loaded
    var externalizableIdCheckbox = document.getElementById("externalizableId");
    if (externalizableIdCheckbox) {
        externalizableIdCheckbox.addEventListener("click", toggleFields);
    }
    
    // Initialize scan type checkboxes
    initializeScanTypeCheckboxes();
}); 