// Use this to enter all you custom js functions
function loadSubcounties(countySelectorId = '#county', subcountySelectorId = '#subcounty', url = '/get-subcounties/') {
    $(countySelectorId).on('change', function () {
        const countyId = $(this).val();

        const $subcountySelect = $(subcountySelectorId);
        $subcountySelect.empty().append('<option value="">-- Select Subcounty --</option>');

        if (countyId) {
            $.ajax({
                url: url,
                data: {'county_id': countyId},
                success: function (data) {
                    $.each(data, function (i, item) {
                        $subcountySelect.append($('<option>', {
                            value: item.id,
                            text: item.name
                        }));
                    });
                },
                error: function (xhr, status, error) {
                    console.error('Error fetching subcounties:', error);
                }
            });
        }
    });
}

// Call the function after the DOM is ready
$(document).ready(function () {
    loadSubcounties(); // uses default IDs
});

