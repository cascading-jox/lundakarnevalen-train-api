use std::{
    fs::{self, File},
    io::{BufReader, Read},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};

use actix_web::{
    dev::ServiceRequest,
    get, middleware,
    web::{self, Data},
    App, Error, HttpResponse, HttpServer, Responder, Result,
};

use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};

use actix_web_httpauth::{
    extractors::{
        bearer::{BearerAuth, Config},
        AuthenticationError,
    },
    middleware::HttpAuthentication,
};

use std::env;

#[derive(Serialize, Deserialize, Debug)]
struct Position {
    latitude: f64,
    longitude: f64,
    accuracy: f32,
    altitude_accuracy: Option<f32>,
    altitude: Option<f32>,
    speed: Option<f32>,
    heading: Option<f32>,
    update_time: Option<String>,
}

impl Default for Position {
    fn default() -> Self {
        Self {
            latitude: 0.0,
            longitude: 0.0,
            accuracy: 0.0,
            altitude_accuracy: None,
            altitude: None,
            speed: None,
            heading: None,
            update_time: None,
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let key = "TRAIN_API_PORT";
    let mut port: String = "8080".to_string();
    match env::var(key) {
        Ok(val) => port = val.to_string(),
        Err(e) => log::warn!("couldn't interpret {}: {}", key, e),
    }

    log::info!("starting HTTP server at https://localhost:{port}");

    let config = load_rustls_config();

    let testing_position_index = web::Data::new(Mutex::new(0));

    let current_position = match read_position_from_disk() {
        Ok(position) => web::Data::new(Mutex::new(position)),
        Err(e) => {
            log::warn!("Failed to read position from disk: {e}. Using default position.");
            // return default position from function
            get_default_position()
        }
    };

    HttpServer::new(move || {
        let auth_middleware = HttpAuthentication::bearer(bearer_auth_validate);
        App::new()
            .wrap(middleware::Logger::default()) // enable logger
            .wrap(middleware::Compress::default()) // enable compression
            .app_data(Data::clone(&current_position))
            .app_data(Data::clone(&testing_position_index))
            .app_data(web::JsonConfig::default().limit(4096))
            .service(get_position)
            .service(get_testing_position)
            .service(
                // service behind authentication
                web::resource("/train/set-position")
                    .wrap(auth_middleware)
                    .route(web::post().to(set_position)),
            )
    })
    .bind_rustls("[::]:".to_owned() + &port, config)?
    .run()
    .await
}

#[get("/train/get-testing-position")]
/// only for testing! returns a Position from an array of 20 predefined positions that increment with each request
async fn get_testing_position(testing_position_index: web::Data<Mutex<i32>>) -> impl Responder {
    let positions = vec![
        Position {
            latitude: 55.70362,
            longitude: 13.194198,
            ..Default::default()
        },
        Position {
            latitude: 55.70369,
            longitude: 13.194284,
            ..Default::default()
        },
        Position {
            latitude: 55.704356,
            longitude: 13.194541,
            ..Default::default()
        },
        Position {
            latitude: 55.704377,
            longitude: 13.194568,
            ..Default::default()
        },
        Position {
            latitude: 55.704397,
            longitude: 13.194615,
            ..Default::default()
        },
        Position {
            latitude: 55.704948,
            longitude: 13.194902,
            ..Default::default()
        },
        Position {
            latitude: 55.705654,
            longitude: 13.195353,
            ..Default::default()
        },
        Position {
            latitude: 55.707134,
            longitude: 13.19641,
            ..Default::default()
        },
        Position {
            latitude: 55.707459,
            longitude: 13.196541,
            ..Default::default()
        },
        Position {
            latitude: 55.707608,
            longitude: 13.196382,
            ..Default::default()
        },
        Position {
            latitude: 55.707718,
            longitude: 13.19639,
            ..Default::default()
        },
        Position {
            latitude: 55.707836,
            longitude: 13.196417,
            ..Default::default()
        },
        Position {
            latitude: 55.707945,
            longitude: 13.196366,
            ..Default::default()
        },
        Position {
            latitude: 55.708024,
            longitude: 13.196237,
            ..Default::default()
        },
        Position {
            latitude: 55.708859,
            longitude: 13.194317,
            ..Default::default()
        },
        Position {
            latitude: 55.709002,
            longitude: 13.193893,
            ..Default::default()
        },
        Position {
            latitude: 55.709093,
            longitude: 13.19355,
            ..Default::default()
        },
        Position {
            latitude: 55.709175,
            longitude: 13.1928,
            ..Default::default()
        },
        Position {
            latitude: 55.708931,
            longitude: 13.192779,
            ..Default::default()
        },
        Position {
            latitude: 55.70778,
            longitude: 13.192731,
            ..Default::default()
        },
        Position {
            latitude: 55.706427,
            longitude: 13.192575,
            ..Default::default()
        },
        Position {
            latitude: 55.706221,
            longitude: 13.192578,
            ..Default::default()
        },
        Position {
            latitude: 55.706229,
            longitude: 13.192345,
            ..Default::default()
        },
        Position {
            latitude: 55.706327,
            longitude: 13.191578,
            ..Default::default()
        },
        Position {
            latitude: 55.706398,
            longitude: 13.191181,
            ..Default::default()
        },
        Position {
            latitude: 55.706795,
            longitude: 13.188426,
            ..Default::default()
        },
        Position {
            latitude: 55.70681,
            longitude: 13.188056,
            ..Default::default()
        },
        Position {
            latitude: 55.706806,
            longitude: 13.187577,
            ..Default::default()
        },
        Position {
            latitude: 55.705552,
            longitude: 13.187582,
            ..Default::default()
        },
        Position {
            latitude: 55.704821,
            longitude: 13.187668,
            ..Default::default()
        },
        Position {
            latitude: 55.704223,
            longitude: 13.187807,
            ..Default::default()
        },
        Position {
            latitude: 55.70413,
            longitude: 13.189094,
            ..Default::default()
        },
        Position {
            latitude: 55.704016,
            longitude: 13.191245,
            ..Default::default()
        },
        Position {
            latitude: 55.703838,
            longitude: 13.192661,
            ..Default::default()
        },
        Position {
            latitude: 55.703146,
            longitude: 13.192623,
            ..Default::default()
        },
        Position {
            latitude: 55.702344,
            longitude: 13.192784,
            ..Default::default()
        },
        Position {
            latitude: 55.702012,
            longitude: 13.195032,
            ..Default::default()
        },
        Position {
            latitude: 55.70197,
            longitude: 13.195112,
            ..Default::default()
        },
        Position {
            latitude: 55.701889,
            longitude: 13.195176,
            ..Default::default()
        },
        Position {
            latitude: 55.701917,
            longitude: 13.196919,
            ..Default::default()
        },
        Position {
            latitude: 55.702734,
            longitude: 13.19656,
            ..Default::default()
        },
        Position {
            latitude: 55.703042,
            longitude: 13.19652,
            ..Default::default()
        },
        Position {
            latitude: 55.703345,
            longitude: 13.19615,
            ..Default::default()
        },
        Position {
            latitude: 55.703578,
            longitude: 13.195571,
            ..Default::default()
        },
        Position {
            latitude: 55.70363,
            longitude: 13.195362,
            ..Default::default()
        },
        Position {
            latitude: 55.70363,
            longitude: 13.195362,
            ..Default::default()
        },
        Position {
            latitude: 55.703643,
            longitude: 13.195244,
            ..Default::default()
        },
        Position {
            latitude: 55.70362,
            longitude: 13.194198,
            ..Default::default()
        },
    ];

    let mut testing_position_index_locked = match testing_position_index.lock() {
        Ok(mutex) => mutex,
        Err(e) => {
            log::error!("Failed to lock testing_position_index: {}", e);
            return HttpResponse::InternalServerError()
                .body("Failed to lock testing_position_index");
        }
    };
    // save positions of testing_position_index to a variable
    let testing_position_index = *testing_position_index_locked;
    *testing_position_index_locked += 1;

    let testing_position = &positions[testing_position_index as usize % positions.len()];

    // return first value in vec
    HttpResponse::Ok().json(testing_position)
}

/// sets the current position to payload
async fn set_position(
    current_position: web::Data<Mutex<Position>>,
    payload: web::Json<Position>,
) -> HttpResponse {
    // set current_position to payload
    let mut current_position = if let Ok(guard) = current_position.lock() {
        guard
    } else {
        return HttpResponse::Conflict().finish();
    };
    // set current_position to payload
    *current_position = payload.into_inner();
    match write_position_to_disk(&current_position) {
        Ok(_) => log::info!("Wrote position to disk."),
        Err(e) => log::error!("Failed to write position to disk: {e}."),
    }
    HttpResponse::Ok().finish()
}

/// Writes the current_position to "position.json"
fn write_position_to_disk(current_position: &Position) -> std::io::Result<()> {
    let current_position_string = serde_json::to_string(&current_position)?;

    let key = "TRAIN_API_POSITION_FILE";
    let mut value: String = "position.json".to_string();
    match env::var(key) {
        Ok(val) => value = val.to_string(),
        Err(e) => log::warn!("couldn't interpret {}: {}", key, e),
    }

    // save default position to disk using write
    fs::write(value, current_position_string)?;
    Ok(())
}

/// returns the current_position variable.
/// should return:
/// ```
/// {
///      latitude: f64,
///      longitude: f64,
///      accuracy: f32,
///      altitudeAccuracy: f32 || null,
///      altitude: f32 || null,
///      speed: f32 || null,
///      heading: f32 || null,
///      update_time: String || null,
/// }
/// ```
#[get("/train/get-position")]
async fn get_position(current_position: web::Data<Mutex<Position>>) -> HttpResponse {
    HttpResponse::Ok().json(web::Json(current_position))
}

async fn bearer_auth_validate(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, Error> {
    let key = "TRAIN_API_CRED_TOKEN";
    let token: String;
    match env::var(key) {
        Ok(val) => token = val.to_string(),
        Err(e) => panic!("No authentication token in {}!: {}", key, e),
    }

    if credentials.token() == token {
        Ok(req)
    } else {
        let config = req
            .app_data::<Config>()
            .map(|data| data.clone())
            .unwrap_or_else(Default::default);

        Err(AuthenticationError::from(config).into())
    }
}

fn load_rustls_config() -> rustls::ServerConfig {
    // init server config builder with safe defaults
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();

    let key = "TRAIN_API_CERT_FILE";
    let cert: String;
    match env::var(key) {
        Ok(val) => cert = val.to_string(),
        Err(e) => panic!("couldn't interpret {}: {}", key, e),
    }

    let key = "TRAIN_API_KEY_FILE";
    let priv_key: String;
    match env::var(key) {
        Ok(val) => priv_key = val.to_string(),
        Err(e) => panic!("couldn't interpret {}: {}", key, e),
    }

    // load TLS key/cert files
    let cert_file = &mut BufReader::new(File::open(cert).unwrap());
    let key_file = &mut BufReader::new(File::open(priv_key).unwrap());

    // convert files to key/cert objects
    let cert_chain = certs(cert_file)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)
        .unwrap()
        .into_iter()
        .map(PrivateKey)
        .collect();

    // exit if no keys could be parsed
    if keys.is_empty() {
        log::error!("Could not locate PKCS 8 private keys.");
        std::process::exit(1);
    }

    config.with_single_cert(cert_chain, keys.remove(0)).unwrap()
}

/// returns a default position and writes it to disk
fn get_default_position() -> actix_web::web::Data<Mutex<Position>> {
    let default_position = Position {
        latitude: 0.0,
        longitude: 0.0,
        accuracy: 0.0,
        altitude_accuracy: None,
        altitude: None,
        speed: None,
        heading: None,
        update_time: None,
    };
    // convert default_position to string
    let default_position_string = match serde_json::to_string(&default_position) {
        Ok(position_string) => position_string,
        Err(e) => {
            log::error!("Failed to convert default position to string: {e}. Returning early without writing to disk.");
            // return early without writing to disk
            return web::Data::new(Mutex::new(default_position));
        }
    };

    let key = "TRAIN_API_POSITION_FILE";
    let mut value: String = "position.json".to_string();
    match env::var(key) {
        Ok(val) => value = val.to_string(),
        Err(e) => log::warn!("couldn't interpret {}: {}", key, e),
    }

    // save default position to disk using write
    match fs::write(value, default_position_string) {
        Ok(_) => (),
        Err(e) => log::error!("Failed to write default position to disk: {e}"),
    };
    web::Data::new(Mutex::new(default_position))
}

/// reads position from disk and returns the position
fn read_position_from_disk() -> std::io::Result<Position> {
    let key = "TRAIN_API_POSITION_FILE";
    let mut value: String = "position.json".to_string();
    match env::var(key) {
        Ok(val) => value = val.to_string(),
        Err(e) => log::warn!("couldn't interpret {}: {}", key, e),
    }

    let mut file = File::open(value)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let position: Position = serde_json::from_str(&contents)?;
    Ok(position)
}

// TODO: fix empty stream bug
/* #[cfg(test)]
mod tests {
    use super::*;
    use actix_web::body::to_bytes;
    use actix_web::dev::Service;
    use actix_web::web::Bytes;
    use actix_web::{http, test, web, App};

    trait BodyTest {
        fn as_str(&self) -> &str;
    }

    impl BodyTest for Bytes {
        fn as_str(&self) -> &str {
            std::str::from_utf8(self).unwrap()
        }
    }

    #[actix_web::test]
    async fn test_set_position() {
        let current_position = match read_position_from_disk() {
            Ok(position) => web::Data::new(Mutex::new(position)),
            Err(e) => {
                log::error!("Error reading file: {}. Using default position. ", e);
                // return default position from function
                get_default_position()
            }
        };

        let app = test::init_service(
            App::new()
                .app_data(Data::clone(&current_position))
                // .app_data(current_position.clone())
                .app_data(web::JsonConfig::default().limit(4096))
                .service(set_position)
                .service(get_position),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/train/set-position")
            .set_json(&Position {
                latitude: 0.0,
                longitude: 0.0,
                accuracy: 0.0,
                altitude_accuracy: Some(0.0),
                altitude: Some(0.0),
                speed: Some(0.0),
                heading: Some(0.0),
            })
            .to_request();
        let resp = app.call(req).await.unwrap();

        assert_eq!(resp.status(), http::StatusCode::OK);

        // BUG: why is body empty?
        let body = to_bytes(resp.into_body()).await.unwrap();
        assert_eq!(
            body.as_str(),
            r#####"{"latitude":0.0,"longitude":0.0,"accuracy":0.0,"altitude_accuracy":0.0,"altitude":0.0,"speed":0.0,"heading":0.0}"#####
        );
    }
}
 */
