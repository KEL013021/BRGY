// Helper function to reset dropdown with placeholder
    function setPlaceholder(dropdown, text) {
        dropdown.empty();
        dropdown.append('<option value="" disabled selected hidden>' + text + '</option>');
    }

    var my_handlers = {
        // Fill provinces
        fill_provinces: function () {
            var region_code = $(this).val();
            var region_text = $(this).find("option:selected").text();
            $('#region-text').val(region_text);

            // clear inputs
            $('#province-text').val('');
            $('#city-text').val('');
            $('#barangay-text').val('');

            // reset dropdowns
            let province = $('#province');
            let city = $('#city');
            let barangay = $('#barangay');

            setPlaceholder(province, 'Choose State/Province');
            setPlaceholder(city, 'Choose City/Municipality');
            setPlaceholder(barangay, 'Choose Barangay');

            // load provinces
            var url = '/ajax/ph-json/province.json';
            $.getJSON(url, function (data) {
                var result = data.filter(value => value.region_code == region_code);

                result.sort((a, b) => a.province_name.localeCompare(b.province_name));

                $.each(result, function (key, entry) {
                    province.append(
                        $('<option></option>')
                            .attr('value', entry.province_code)
                            .text(entry.province_name)
                    );
                });
            });
        },

        // Fill cities
        fill_cities: function () {
            var province_code = $(this).val();
            var province_text = $(this).find("option:selected").text();
            $('#province-text').val(province_text);

            $('#city-text').val('');
            $('#barangay-text').val('');

            let city = $('#city');
            let barangay = $('#barangay');

            setPlaceholder(city, 'Choose City/Municipality');
            setPlaceholder(barangay, 'Choose Barangay');

            var url = '/ajax/ph-json/city.json';
            $.getJSON(url, function (data) {
                var result = data.filter(value => value.province_code == province_code);

                result.sort((a, b) => a.city_name.localeCompare(b.city_name));

                $.each(result, function (key, entry) {
                    city.append(
                        $('<option></option>')
                            .attr('value', entry.city_code)
                            .text(entry.city_name)
                    );
                });
            });
        },

        // Fill barangays
        fill_barangays: function () {
            var city_code = $(this).val();
            var city_text = $(this).find("option:selected").text();
            $('#city-text').val(city_text);

            $('#barangay-text').val('');

            let barangay = $('#barangay');
            setPlaceholder(barangay, 'Choose Barangay');

            var url = '/ajax/ph-json/barangay.json';
            $.getJSON(url, function (data) {
                var result = data.filter(value => value.city_code == city_code);

                result.sort((a, b) => a.brgy_name.localeCompare(b.brgy_name));

                $.each(result, function (key, entry) {
                    barangay.append(
                        $('<option></option>')
                            .attr('value', entry.brgy_code)
                            .text(entry.brgy_name)
                    );
                });
            });
        },

        // On change barangay
        onchange_barangay: function () {
            var barangay_text = $(this).find("option:selected").text();
            $('#barangay-text').val(barangay_text);
        }
    };

    $(function () {
        // Events
        $('#region').on('change', my_handlers.fill_provinces);
        $('#province').on('change', my_handlers.fill_cities);
        $('#city').on('change', my_handlers.fill_barangays);
        $('#barangay').on('change', my_handlers.onchange_barangay);

        // Load regions
        let dropdown = $('#region');
        setPlaceholder(dropdown, 'Choose Region');

        const url = '/ajax/ph-json/region.json';
        $.getJSON(url, function (data) {
            $.each(data, function (key, entry) {
                dropdown.append(
                    $('<option></option>')
                        .attr('value', entry.region_code)
                        .text(entry.region_name)
                );
            });
        });
    });
