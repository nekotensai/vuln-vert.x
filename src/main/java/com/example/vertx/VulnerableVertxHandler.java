package com.example.vertx;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.SqlClient;

public class VulnerableVertxHandler extends AbstractVerticle {

  private Pool pool;

  //SQL Injection
  public void handleUserQuery(HttpServerRequest request) {
    String userId = request.getParam("userId");
    String query = "SELECT * FROM users WHERE id = " + userId; // Direct concatenation

    pool.query(query).execute().onComplete(ar -> {
      if (ar.succeeded()) {
        request.response().end("User found");
      }
    });
  }   

  // XSS via reflected parameter
  public void handleGreeting(HttpServerRequest request) {
    String name = request.getParam("name");
    request.response().end("<h1>Hello " + name + "</h1>"); // No encoding
  }

  //Path Traversal
  public void handleFileRead(HttpServerRequest request) {
    String filename = request.getParam("file");
    vertx.fileSystem().readFile(filename).onComplete(result -> { //User-controlled path
      if (result.succeeded()) {
        request.response().end(result.result());
      }
    });
  }

  // SAFE: Parameterized query 
  public void handleUserQuerySafe(HttpServerRequest request) {
    String userId = request.getParam("userId");
    pool.preparedQuery("SELECT * FROM users WHERE id = ?")
      .execute(io.vertx.sqlclient.Tuple.of(userId)).onComplete( ar -> {
        if (ar.succeeded()) {
          request.response().end("User found");
        }
      });
  }
}
