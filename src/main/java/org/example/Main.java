package org.example;

import io.javalin.Javalin;
import org.example.scanner.IPScanner;

import static io.javalin.rendering.template.TemplateUtil.model;

public class Main {
    public static void main(String[] args) {

        Javalin app = Javalin.create(config->{
            config.staticFiles.add("/static");
        }).start(7000);

        app.get("/", ctx -> {
            ctx.render("templates/template.html");
        });

        app.post("/scan",ctx->{
            System.out.println("new request");
            String ip = ctx.formParam("ip");
            int threadsCount = Integer.parseInt(ctx.formParam("threads"));

            if(threadsCount<=0)
                threadsCount = 1;

            try{
                IPScanner scanner = new IPScanner();
                try{
                    scanner.scan(ip,threadsCount);
                }
                catch (Exception e){
                    System.out.println(e.getMessage());
                    scanner.terminateClient();
                    ctx.status(500);
                }
                finally {
                    scanner.terminateClient();
                    ctx.render("templates/template.html");
                }
            }
            catch (Exception e){
                System.out.println(e.getMessage());
                ctx.status(500);
            }
            ctx.status(200);
        });
    }
}