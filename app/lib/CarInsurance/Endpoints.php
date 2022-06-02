<?php

namespace CarInsurance;

class Endpoints {
    public const API_URL = '/api/';
    public const API_AUTHORIZATION = self::API_URL . 'authorization';
    public const API_AUTHSTATS = self::API_URL . 'authStats';
    public const API_ACCOUNTS = self::API_URL . 'accounts';
    public const API_CATEGORIES = self::API_URL . 'categories';
    public const API_RESOURCES = self::API_URL . 'resources';
    public const API_MAIN_PRODUCTS = self::API_URL . 'mainProducts';
    public const API_SUB_PRODUCTS = self::API_URL . 'subProducts';
    public const API_ESTIMATIONS = self::API_URL . 'estimations';
    public const API_ORDERS = self::API_URL . 'orders';
    public const API_RATING = self::API_URL . 'rating';
    public const API_VEHICLES = self::API_URL . 'vehicles';
    public const API_VEHICLES_DATA = self::API_URL . 'vehiclesData';
    public const API_ACCESSORIES = self::API_URL . 'accessories';
    public const API_ASSETS = self::API_URL . 'assets';
    public const API_PAYMENT = self::API_URL . 'payment';
    public const API_LOGS = self::API_URL . 'logs';
    
    public const YOCO_PAYMENT_URL = "https://online.yoco.com/v1/charges/";
}