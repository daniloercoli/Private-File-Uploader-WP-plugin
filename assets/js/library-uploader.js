/* global jQuery, plupload */
jQuery(function($) {
    if (!window.PRIVFILEUP_UPLOADER) return;

    var cfg = window.PRIVFILEUP_UPLOADER;

    $('.privfileup-delete-file').on('click', function(event) {
        if (!window.confirm(cfg.strings.confirmDelete)) {
            event.preventDefault();
        }
    });

    function useOriginalImage() {
        var fallback = this.getAttribute('data-fallback');
        if (fallback) {
            this.removeAttribute('data-fallback');
            this.src = fallback;
        }
    }

    $('.privfileup-thumb[data-fallback]').on('error', useOriginalImage).each(function() {
        if (this.complete && this.naturalWidth === 0) {
            useOriginalImage.call(this);
        }
    });
    var $box = $('#privfileup-uploader');
    var $progress = $('#privfileup-progress');
    var $list = $('#privfileup-list');

    var uploader = new plupload.Uploader({
        browse_button: 'privfileup-pick',
        container: 'privfileup-uploader',
        drop_element: 'privfileup-uploader',
        url: cfg.restUrl,
        runtimes: 'html5,html4',
        multi_selection: true,
        headers: {
            'X-WP-Nonce': cfg.restNonce
        },
        multipart: true,
        multipart_params: {},
        file_data_name: 'file',
        filters: {
            max_file_size: cfg.maxBytes > 0 ? (cfg.maxBytes + 'b') : undefined
        }
    });

    uploader.bind('Init', function() {
        var el = document.getElementById('privfileup-uploader');
        el.addEventListener('dragover', function() {
            $box.addClass('dragover');
        });
        el.addEventListener('dragleave', function() {
            $box.removeClass('dragover');
        });
        el.addEventListener('drop', function() {
            $box.removeClass('dragover');
        });
    });

    uploader.bind('FilesAdded', function(up, files) {
        $progress.show().text(cfg.strings.uploading);
        plupload.each(files, function(file) {
            var row = $('<div/>', {
                    'class': 'privfileup-uploader-item',
                    id: 'privfileup-' + file.id
                })
                .append($('<span/>').text(file.name + ' (' + plupload.formatSize(file.size) + ')'))
                .append($('<span/>', {
                    'class': 'privfileup-status',
                    text: '0%'
                }));
            $list.append(row);
        });
        up.refresh();
        up.start();
    });

    uploader.bind('UploadProgress', function(up, file) {
        $('#privfileup-' + file.id + ' .privfileup-status').text(file.percent + '%');
    });

    uploader.bind('FileUploaded', function(up, file, info) {
        try {
            var res = JSON.parse(info.response || '{}');
            $('#privfileup-' + file.id + ' .privfileup-status').text(res && res.ok ? cfg.strings.done : cfg.strings.failed);
        } catch (e) {
            $('#privfileup-' + file.id + ' .privfileup-status').text(cfg.strings.failed);
        }
    });

    uploader.bind('Error', function(up, err) {
        var msg = err && err.message ? err.message : cfg.strings.error;
        var fileId = err.file && err.file.id ? err.file.id : null;
        if (fileId) {
            $('#privfileup-' + fileId + ' .privfileup-status').text(cfg.strings.failed + ' – ' + msg);
        } else {
            $list.append($('<div/>', {
                'class': 'privfileup-uploader-item'
            }).text(cfg.strings.failed + ' – ' + msg));
        }
    });

    uploader.bind('UploadComplete', function() {
        location.reload(); // refresh the table
    });

    uploader.init();
});
