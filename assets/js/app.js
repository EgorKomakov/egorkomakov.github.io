"use strict";

document.addEventListener('DOMContentLoaded', function () {
  // --- Существующий код меню ---
  var burgerButton = document.getElementById('button-burger');
  var menu = document.getElementById('menu');
  burgerButton && burgerButton.addEventListener('click', function () {
  menu.classList.toggle('show');
  const isExpanded = this.getAttribute('aria-expanded') === 'true';
  this.setAttribute('aria-expanded', !isExpanded);

  if (window.innerWidth < 1024) {
        document.body.style.overflow = menu.classList.contains('show') ? 'hidden' : '';
    }
});
  
  document.querySelectorAll('#menu a').forEach(function(link) {
    link.addEventListener('click', function() {
        if (window.innerWidth < 1024) {
            menu.classList.remove('show');
            burgerButton.classList.remove('active');
            burgerButton.setAttribute('aria-expanded', 'false');
            document.body.style.overflow = '';
        }
    });
});

  // --- Существующий код плавного скролла ---
  document.querySelectorAll('a[href^="#"]').forEach(function (anchor) {
    anchor.addEventListener('click', function (e) {
      e.preventDefault();
      document.querySelector(this.getAttribute('href')).scrollIntoView({
        behavior: 'smooth'
      });
    });
  });

  // --- Фиксация меню при скролле (для mobile/tablet) ---
  var navbar = document.querySelector('.navbar');
  window.addEventListener('scroll', function() {
    if (window.innerWidth < 1024) {
      if (window.scrollY > 50) {
        navbar.classList.add('scrolled');
      } else {
        navbar.classList.remove('scrolled');
      }
    }
  });

  // --- Кнопка "Наверх" ---
  var scrollToTopBtn = document.createElement('button');
  scrollToTopBtn.id = 'scrollToTopBtn';
  scrollToTopBtn.className = 'scroll-to-top-btn';
  scrollToTopBtn.innerHTML = '↑';
  scrollToTopBtn.setAttribute('aria-label', 'Scroll to top');
  document.body.appendChild(scrollToTopBtn);

  // Показ/скрытие кнопки при скролле
  window.addEventListener('scroll', function() {
    if (window.scrollY > 300) {
      scrollToTopBtn.classList.add('show');
    } else {
      scrollToTopBtn.classList.remove('show');
    }
  });

  // Обработчик клика по кнопке
  scrollToTopBtn.addEventListener('click', function() {
    window.scrollTo({
      top: 0,
      behavior: 'smooth'
    });
  });

  // --- Существующие функции ---
  var wentAboard = function wentAboard(parentElem, childElem) {
    var parentRect = parentElem.getBoundingClientRect();
    var childRect = childElem.getBoundingClientRect();
    return childRect.left < parentRect.left || childRect.right > parentRect.right;
  };

  var hideWhenOutOfBounds = function hideWhenOutOfBounds(container, elem) {
    return wentAboard(container, elem) ? elem.classList.add('hide') : elem.classList.remove('hide');
  };

  // --- Существующие инициализации ---
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