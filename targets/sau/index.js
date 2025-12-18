(function($) {
  function randomName() {
    var name = Math.random().toString(36).substring(2, 9);
    $("#basket_name").val(name);
  }

  function onAjaxError(jqXHR) {
    if (jqXHR.status == 401) {
      $("#master_token_dialog").modal({ keyboard : false });
    } else {
      $("#error_message_label").html("HTTP " + jqXHR.status + " - " + jqXHR.statusText);
      $("#error_message_text").html(jqXHR.responseText);
      $("#error_message").modal();
    }
  }

  function addBasketName(name) {
    $("#empty_list").addClass("hide");
    $("#baskets").append("<li id='basket_" + name + "'><a href='/web/" + name + "'>" + name + "</a></li>");
  }

  function showMyBaskets() {
    $("#empty_list").removeClass("hide");
    for (var i = 0; i < localStorage.length; i++) {
      var key = localStorage.key(i);
      if (key && key.indexOf("basket_") == 0) {
        addBasketName(key.substring("basket_".length));
      }
    }
  }

  function createBasket() {
    var basket = $.trim($("#basket_name").val());
    if (basket) {
      $.ajax({
        method: "POST",
        url: "/api/baskets/" + basket,
        headers: {
          "Authorization" : sessionStorage.getItem("master_token")
        }
      }).done(function(data) {
          localStorage.setItem("basket_" + basket, data.token);
          $("#created_message_text").html("<p>Basket '" + basket +
            "' is successfully created!</p><p>Your token is: <mark>" + data.token + "</mark></p>");
          $("#basket_link").attr("href", "/web/" + basket);
          $("#created_message").modal();


          addBasketName(basket);
        }).always(function() {
          randomName();
        }).fail(onAjaxError);
    } else {
      $("#error_message_label").html("Missing basket name");
      $("#error_message_text").html("Please, provide a name of basket you would like to create");
      $("#error_message").modal();
    }
  }

  function saveMasterToken() {
    var token = $("#master_token").val();
    $("#master_token").val("");
    $("#master_token_dialog").modal("hide");
    if (token) {
      sessionStorage.setItem("master_token", token);
    } else {
      sessionStorage.removeItem("master_token");
    }
  }


  $(document).ready(function() {
    $("#base_uri").html(window.location.protocol + "//" + window.location.host + "/");
    $("#create_basket").on("submit", function(event) {
      createBasket();
      event.preventDefault();
    });
    $("#refresh").on("click", function(event) {
      randomName();
    });
    $("#master_token_dialog").on("hidden.bs.modal", function (event) {
      saveMasterToken();
    });
    randomName();
    showMyBaskets();
  });
})(jQuery);

