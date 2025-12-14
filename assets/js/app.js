"use strict";

document.addEventListener('DOMContentLoaded', function () {
  var burgerButton = document.getElementById('button-burger');
  var menu = document.getElementById('menu');
  burgerButton && burgerButton.addEventListener('click', function () {
    menu.classList.toggle('show');
  });
  document.querySelectorAll('a[href^="#"]').forEach(function (anchor) {
    anchor.addEventListener('click', function (e) {
      e.preventDefault();
      document.querySelector(this.getAttribute('href')).scrollIntoView({
        behavior: 'smooth'
      });
    });
  });

  var wentAboard = function wentAboard(parentElem, childElem) {
    var parentRect = parentElem.getBoundingClientRect();
    var childRect = childElem.getBoundingClientRect();
    return childRect.left < parentRect.left || childRect.right > parentRect.right;
  };

  var hideWhenOutOfBounds = function hideWhenOutOfBounds(container, elem) {
    return wentAboard(container, elem) ? elem.classList.add('hide') : elem.classList.remove('hide');
  };

  new WOW().init();
  new Swiper('.giftset-collections', {
    slidesPerView: 1,
    effect: 'fade',
    fadeEffect: {
      crossFade: true
    },
    pagination: {
      el: '.giftset-tabs .tabs-menu',
      type: 'bullets',
      clickable: true,
      bulletClass: 'tab',
      bulletActiveClass: 'active',
      renderBullet: function renderBullet(index) {
        return "<li class=\"tab\">".concat(index + 1, "</li>");
      }
    }
  });
  new Swiper('.coffee-products', {
    spaceBetween: 30,
    slidesPerView: 'auto',
    navigation: {
      nextEl: '#coffee-button-next',
      prevEl: '#coffee-button-prev'
    }
  }).on('transitionEnd', function () {
    var coffeeProductsContainer = document.getElementsByClassName('coffee-products')[0];
    var coffeeCards = document.querySelectorAll('.coffee-products .short-product-card');
    coffeeCards.forEach(function (item) {
      hideWhenOutOfBounds(coffeeProductsContainer, item);
    });
  });
  new Swiper('.coffee-combo-products', {
    spaceBetween: 30,
    slidesPerView: 'auto',
    navigation: {
      nextEl: '#coffee-combo-button-next',
      prevEl: '#coffee-combo-button-prev'
    }
  }).on('transitionEnd', function () {
    var coffeeComboProductsContainer = document.getElementsByClassName('coffee-combo-products')[0];
    var coffeeComboCards = document.querySelectorAll('.coffee-combo-products .product-card');
    coffeeComboCards.forEach(function (item) {
      hideWhenOutOfBounds(coffeeComboProductsContainer, item);
    });
  });
});
//# sourceMappingURL=app.js.map
