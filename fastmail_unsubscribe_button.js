// ==UserScript==
// @name         Add unsubscribe button
// @namespace    http://tampermonkey.net/
// @version      2025-04-15
// @description  try to take over the world!
// @author       You
// @match        https://app.fastmail.com/mail/*
// @icon         https://www.google.com/s2/favicons?sz=64&domain=fastmail.com
// @grant        none
// ==/UserScript==

(function() {
    'use strict';
    console.log("Loading custom code!");

    var onEmailLoaded = function(resolve) {
        var filter = "div.v-Message";
        var filters = document.querySelectorAll(filter);
        if (filters && filters.length > 0) {
            filters.forEach(function(filter) {
                resolve(filter)
            })
        } else {
            window.setTimeout(function() {
                console.log("Filters not visible, relaunching timer");
                onEmailLoaded(resolve);
            }, 100);
        }
    }

    onEmailLoaded(function(elements) {
        var linksFromEmail = document.querySelectorAll("div.v-Message a");
        console.log(`Found ${linksFromEmail.length} links in this email`);

        // check if one of them matches unsubscribe button
        linksFromEmail.forEach(function(link) {
            var regexps = [
                /unsubscribe/i,
                /désabonner/i,
             ];
            regexps.forEach(function(regex) {
            if (link.textContent.match(/désabonner/)) {
                console.log(`This link ${link} is probably an unsubscribe link`);
                addUnsubscribeButton(link);
            }
            })
        });
    });

    var addUnsubscribeButton = function(link) {
        var toolbars = document.querySelectorAll("div.v-Toolbar");
        // the list one is the one we want to update
        var toolbarToUpdate = toolbars[toolbars.length - 1];
        // here we should add a button next to them
        var newButton = document.createElement("button");
        newButton.class = "v-Button v-Button--subtleStandard v-Button--sizeM s-delete has-icon";
        var span = document.createElement("span");
        span.class = "label"
        span.innerText = "Delete";
        newButton.appendChild(span);
        toolbarToUpdate.appendChild(newButton);
    }

    
})();
