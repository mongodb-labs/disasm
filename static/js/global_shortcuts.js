var globalListener = new window.keypress.Listener();
globalListener.register_many([
    {
        "keys"          : "?",
        "on_keydown"    : function() {
            $.colorbox({
                href: "static/html/help.html", 
            });
        }
    },
]);