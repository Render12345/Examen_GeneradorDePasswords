<?php

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

require_once '../core/Router.php';
require_once '../core/Respuesta.php';
require_once '../resources/v1/GeneradorResource.php';
require_once '../resources/v1/ValidadorResource.php';

$basePath = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME']));

$router = new Router('v1', $basePath);

$generadorResource = new GeneradorResource();
$validadorResource = new ValidadorResource();

$router->addRoute('GET',  '/password',          [$generadorResource, 'handleSingle']);
$router->addRoute('POST', '/passwords',         [$generadorResource, 'handleBatch']);
$router->addRoute('POST', '/password/validate', [$validadorResource, 'handle']);

$router->dispatch();
?>