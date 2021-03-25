# Securing a Spring Boot application with IBM AppID

## 1. Create a Spring Boot application

- On the Spring Initializr page <https://start.spring.io/>, generate a Maven Project with the following specifications:

	* Language: Java
	* Dependencies: Spring Web, Spring Security, OAuth2 Resource Server
	* Project Metadata: For this example, we use:
		* Group: com.example
		* Artifact: Product

- Download the project and unzip it.

## 2. Create an instance of IBM AppID service on IBM Cloud

From the the IBM Cloud catalog -> “Security and Identity” category, select the App ID service.

Make sure to select the 'Frankurt (eu-de)' region, select the "Graduated Tier" and give the 'Service name' a name that corresponds to your \<Team name\> so you can find it back afterwards.

Open the newly created Service instance:

- Add a new application
- Give it a name e.g. "mystoreapp"
- Use "regularwebapp" as application type

When you click on the newly created app you should see a JSON structure with all info such as : clientId, tenantId and oAuthServerURL.
Take a note as you will need these values later !

**Create a new role in "Manage Authentication" -> "Profiles and roles" -> "Roles":**

- Give it a name: "Partner"
- Add a scope "mystoreapp/partner"
- Click "Save"

**Create a new user in "Manage Authentication" -> Users**

- This will create a user in the Cloud Directory within your AppID Service. 
- Next assign the "Partner"-role to this newly created user.
- You can also use an existing user if you have already created one.

If you used a Facebook or Google account to login, you can find these users back in "Manage Autentication" -> "Profiles and roles" -> "User Profiles" 

Edit the unzipped Spring Initializr project, and add the following configuration to the src/main/resources/application.yml file with the following property names:

Make sure to replace the issuer-uri with your own !

```
server:
  port: 8000

logging:
  level:
    root: INFO
    org.springframework.web: INFO
    org.springframework.security: INFO
    org.springframework.security.oauth2: INFO

spring:
  security:
    oauth2:
      resourceserver:
        jwt:
            issuer-uri: https://eu-gb.appid.cloud.ibm.com/oauth/v4/70ef0d78-2967-7777-99f8-85939e5d4ca6

```
## 3. Add the protected REST endpoints

Add 3 REST endpoints: 2 GET endpoints (/products and /check) and 1 POST endpoint (/products) to simulate the creation of new product. 

Create a "ProductController.java" class, and add the following code:

```
package com.example.Product;

import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Arrays;
import java.util.List;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin( origins = "http://localhost:8080", allowCredentials = "true")
@RestController
public class ProductController {

    @GetMapping("/products")
    public List<Product> getAllProducts() {
        return Arrays.asList(
            new Product(
                "1",
                "macbook Retina 13.3' ME662 (2013)",
                "3.0GHz Dual-core Haswell Intel Core i5 Turbo Boost up to 3.2 GHz, 3MB L3 cache 8GB (two 4GB SO-DIMMs) of 1600MHz DDR3 SDRAM",
                "https://www.dropbox.com/s/swg9bdr0ejcbtrl/img9.jpg?raw=1",
                10,
                2399
            ),
            new Product(
                "2",
                "Macbook Pro 13.3' Retina MF841LL/A",
                "Macbook Pro 13.3' Retina MF841LL/A Model 2015 Option Ram Care 12/2016",
                "https://www.dropbox.com/s/6tqcep7rk29l59e/img2.jpeg?raw=1",
                15,
                1199
            ),
            new Product(
                "3",
                "Macbook Pro 15.4' Retina MC975LL/A Model 2012",
                "3.0GHz Dual-core Haswell Intel Core i5 Turbo Boost up to 3.2 GHz, 3MB L3 cache 8GB (two 4GB SO-DIMMs) of 1600MHz DDR3 SDRAM",
                "https://www.dropbox.com/s/78fot6w894stu3n/img3.jpg?raw=1",
                1,
                1800
            )
        );
    }

    @GetMapping("/check")
    public boolean greeting(@RequestParam(value = "name", defaultValue = "World") String name,
                           @AuthenticationPrincipal Jwt accessToken) {
        System.out.println("In GET Request");
        String scope = accessToken.getClaims().get("scope").toString();
        Boolean partnerRole = scope.contains("partner");
        System.out.println("Contains sequence 'partner': " + accessToken.getClaims().get("scope").toString());
        System.out.println("Contains sequence 'partner': " + accessToken.getClaims().get("scope").toString().contains("partner"));
        if (partnerRole) {
            return true;
        } else {
            return false;
        }
    }

    @RequestMapping(method = RequestMethod.POST, value = "/products")
    public String addProduct(@RequestBody Product product, @AuthenticationPrincipal Jwt accessToken) {
        System.out.println("In POST Request");
        String scope = accessToken.getClaims().get("scope").toString();
        Boolean partnerRole = scope.contains("partner");
        
        if (partnerRole) {
            System.out.println("Contains sequence 'partner': " + accessToken.getClaims().get("scope").toString());
            System.out.println("Contains sequence 'partner': " + accessToken.getClaims().get("scope").toString().contains("partner"));
            return "Product added";
        } else {
            return "Not Authorized to add product";
        }
    }

}
```
## 4. Add the Product class

Create a "Product.java" class, and add the following code:

```
package com.example.Product;

public class Product {

    private String id;
    private String title;
    private String description;
    private String thumbnail_url;
    private int quantity;
    private float price;

    public Product() {

    }

    public Product(String id, String title, String description, String thumbnail_url, int quantity, float price) {
        super();
        this.id = id;
        this.title = title;
        this.description = description;
        this.thumbnail_url = thumbnail_url;
        this.quantity = quantity;
        this.price = price;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getThumbnail_url() {
        return thumbnail_url;
    }

    public void setThumbnail_url(String thumbnail_url) {
        this.thumbnail_url = thumbnail_url;
    }

    public int getQuantity() {
        return quantity;
    }

    public void setQuantity(int quantity) {
        this.quantity = quantity;
    }

    public float getPrice() {
        return price;
    }

    public void setPrice(int price) {
        this.price = price;
    }

}
```

## 5. Test the Rest service

Launch "Postman" to perform a get request to <http://localhost:8000/check>
(You can install "Postman" as a Google Chrome Extension)

You should get a "401 Unauthorized" status code.
In order to perform a valid request, you will need an accesstoken to include in your GET request.
You can obtain such an accesstoken by opening a browser session to the following URL: <http://localhost:3000/login>
(If you deployed the authentication application from previous exercise, this should still work and prompt you with a AppId login). Check the the Network communication in your Browser development tools for the request http://localhost:8080/loginwithtoken?name=....
The accesstoken is a parameter as part from this URL and can be copied to be used in 'Postman'.

Within 'Postman' click oin the tab 'Authorization' as part of your GET request and select the type 'Bearer Token'.
Paste the accesstoken you copied earlier into the token field and click 'SEND'.

You should now get a '200 OK' status code and a response text 'true'.

You can also verify the decoded contents of the JWT accesstoken via <http://jwt.io>

## 6. Create a new VueJS application

In order to test the protected service, we can create a new VueJS application or modify the application you already have from the previous exercise/workshop.
We also need to install an additional module 'axios' for HTTP POST requests used in the code.

```
# npm install -g @vue/cli
	
# vue create shopping-cart
-> manually select features
-> select Vuex and Router
(use default settings for all next interactive questions)

# cd shopping-cart

# npm install --save axios

# npm run serve
```	

## 7. Add Bootstrap to your project

More info on Bootstrap see: <https://getbootstrap.com/docs/5.0/getting-started/introduction/>

Within "public/index.html" add the following to enable Bootstrap:
	
Add CSS link into \<head> :

```	
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css">
```	

Add Bootstrap bundle scripts into \<body> :

```
<script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/js/bootstrap.bundle.min.js"></script>
```
## 8. Replace the store/index.js with the following code:

```
import Vue from 'vue'
import Vuex from 'vuex'
import axios from 'axios'

Vue.use(Vuex)

export default new Vuex.Store({
  state: {
    user: {
      isAuthenticated: false,
      name: "",
      email: "",
      idToken: "",
      accessToken: "",
      partner: false
    },
    endpoints: {
      login: "http://localhost:3000/login",
      partnercheck: "http://localhost:8000/check",
      products: "http://localhost:8000/products",
    },
  },
  mutations: {
    logout(state) {
      state.user.isAuthenticated = false;
      state.user.name = "";
      state.user.email ="";
      state.user.idToken ="";
      state.user.accessToken = "";
      state.user.partner = "";
    },
    login(state, payload) {
      state.user.isAuthenticated = true;
      state.user.name = payload.name;
      state.user.email =payload.email;
      state.user.idToken =payload.idToken;
      state.user.accessToken =payload.accessToken;
    },
     SET_PARTNER(state, partner) { 
      state.user.partner = partner;
    },
  },
  actions: {
    async checkPartner({ state, commit }) {
      let accessToken = state.user.accessToken;
      console.log("checking partner access", state.endpoints.partnercheck);
      const AuthStr = 'Bearer '.concat(accessToken);
      const AuthHeader = { 'Authorization': AuthStr};
      console.log("AuthToken=",AuthHeader);
      let response = await fetch(state.endpoints.partnercheck, { 
        method: 'GET',
        headers: {
          'Authorization': AuthStr }
        });
      console.log("partneraccess",response);
      if (response.ok) {
        commit('SET_PARTNER', true);
        console.log("TRUE");
      } else {
        commit('SET_PARTNER', false);
        console.log("FALSE");
      }
    },
    registerProduct({ state }, obj) {
      let productsurl = state.endpoints.products;
      console.log(productsurl);
      let accessToken = state.user.accessToken;
      const AuthStr = 'Bearer '.concat(accessToken);
      console.log(AuthStr);
      console.log(obj);
      axios(productsurl, { 
          method: 'POST',
          headers: {
            'Accept': '*/*',
            'Content-Type': 'application/json',
            'Authorization': AuthStr
          },
          credentials: 'include',
          data: obj
      })
      .then(response => {
        console.log('Response:', response);
      })
      .catch((error) => {
        console.error('Error:', error);
      });
    },
  },
  modules: {
  }
})
```

## 9. Add a Navigation Header bar to the Store

* Create a NavHeader.vue file in the src directory

```
<template>
<nav class="navbar navbar-expand-sm navbar-dark bg-dark" role="navigation">
  <div class="container">
    <router-link to="/" class="navbar-brand mr-auto">Blue Store</router-link>
      <ul class="navbar-nav mr-auto">
      </ul>
      <ul class="nav navbar-nav">
        <router-link to="/" tag="li" v-if="!isAuthenticated" class="nav-item" active-class="active">
          <a @click="onLoginClicked" class="nav-link">Login</a>
        </router-link>
        <li v-if="isAuthenticated" class="li-pointer nav-item">
          <div class="dropdown">
            <button class="btn btn-secondary dropdown-toggle" type="button" id="dropdownMenuButton" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
              {{ getUserName() }}
            </button>
            <div class="dropdown-menu" aria-labelledby="dropdownMenuButton">
              <a class="dropdown-item" href="#">Account Settings</a>
              <a v-if="isPartner" @click="onRegisterClicked" class="dropdown-item" href="#">Register Product</a>
              <a @click="onLogoutClicked" class="dropdown-item">Logout {{ userEmail }}</a>
            </div>
          </div>
        </li>
      </ul>
  </div>
</nav>
</template>

<script>
export default {
  components: { },
  name: 'NavHeader',
  computed: {
    userEmail() {
      return this.isLoggedIn ? this.currentUser.email : ''
    },
    isAuthenticated() {
      return this.$store.state.user.isAuthenticated;
    },
    isPartner() {
      return this.$store.state.user.partner;
    },
  },
  methods: {
    onLoginClicked() {
      window.location = this.$store.state.endpoints.login;
    },
    onLogoutClicked() {
      this.$store.commit("logout");
    },
    onRegisterClicked() {
      let obj = { 'description': 'description', 'id': parseInt("1"), 'price': parseInt("1000"), 'quantity': parseInt("10"), 'thumbnail_url': "thumbnail_url", 'title': "title" }
      this.$store.dispatch("registerProduct", obj);
    },
    getUserName() {
      return this.$store.state.user.name;
    }
  }
}
</script>
```

* Add the 'NavHeader' component to App.vue and import it.

Copy and replace the App.vue code with the following:

```
<template>
  <div id="app">
    <NavHeader />
    <router-view/>
  </div>
</template>
	
<script>
import NavHeader from "@/NavHeader.vue"
export default {
  components: {
    NavHeader
  },
  mounted(){
  }
}
</script>
```

## 9. Create a new 'Login.vue' file in the src directory and add thre following code:

```
<template>
  <div class="login">
    <h4 style="margin-top:30px;margin-bottom:30px">Logging in ...</h4>
  </div>
</template>

<script>
export default {
  name: "Login",
  mounted() {
    let name = this.$route.query.name;
    let email = this.$route.query.email;
    let idToken = this.$route.query.id_token;
    let accessToken = this.$route.query.access_token;

    let payload = {
      name: name,
      email: email,
      idToken: idToken,
      accessToken: accessToken
    }

    if (name && email && idToken && name != '' && email != '' && idToken != '') {
      this.$store.commit("login", payload);
      this.$store.dispatch("checkPartner");   
    }
    else {
      this.$store.commit("logout");
    }

    this.$router.push("/");
  }
};
</script>

<style scoped>
</style>
```

The 'Login.vue' will process the redirect to url: http://localhost:8080/loginwithtoken?name=...
which is called after authentication.

## 10. Add a route to 'loginwithtoken' and link it to the component 'Login.vue:

Replace the code in src/route/index.js with the following:

```
import Vue from 'vue'
import VueRouter from 'vue-router'
import Home from '../views/Home.vue'
import Login from '../Login.vue'

Vue.use(VueRouter)

const routes = [
  {
    path: '/',
    name: 'Home',
    component: Home
  },
  { path: '/loginwithtoken', name: 'loginwithtoken', component: Login },
]

const router = new VueRouter({
  mode: 'history',
  base: process.env.BASE_URL,
  routes
})

export default router
```

You should now have a working "Header Bar" in your application which allows you to login and show your name in the header after login.
Check the console for errors. You should see an error "Access to fetch at 'http://localhost:8000/check' from origin 'http://localhost:8080' has been blocked by CORS policy: Response to preflight request doesn't pass access control check: It does not have HTTP ok status."

How come this is not working ? We did a previous test with "Postman" and that worked fine !
That's because browsers behave differently and use a CORS mechanism.

**Cross-Origin Resource Sharing (CORS) is a mechanism that uses additional HTTP headers to tell a browser to let a web application running at one origin (domain) have permission to access selected resources from a server at a different origin.**

Whens accessing resources from another domain, a browser will first initiate a Preflight HTTP request before the actual GET or POST request. You can check these from your networks tab in your browser developer tools or by analysing network traffic using e.g. WireShark.

**A CORS preflight request is a CORS request that checks to see if the CORS protocol is understood and a server is aware using specific methods and headers. It is an OPTIONS request, using three HTTP request headers: Access-Control-Request-Method , Access-Control-Request-Headers , and the Origin header.**

In order to solve this we need to adapt the code on the backend service to allow these kind of requests.

## 11. Add a new "WebSecurityConfiguration.java" class with the following code:

```
package com.example.Product;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Value("partner")
	private String scope;

	@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
	private String issuer;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		.mvcMatchers(HttpMethod.GET, "/products/**").permitAll() // GET requests don't need auth
		.anyRequest()
		.authenticated()
		.and()
		.oauth2ResourceServer()
		.jwt()
		.decoder(jwtDecoder());
	}

  JwtDecoder jwtDecoder() {
	OAuth2TokenValidator<Jwt> withScope = new ScopeValidator(scope);
    //OAuth2TokenValidator<Jwt> withAudience = new AudienceValidator(audience);
    OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuer);
    //OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(withAudience, withIssuer);
	OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(withScope, withIssuer);

    NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) JwtDecoders.fromOidcIssuerLocation(issuer);
    jwtDecoder.setJwtValidator(validator);
    return jwtDecoder;
  }

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(true);
		configuration.setAllowedOrigins(Arrays.asList("http://localhost:8080"));
		configuration.setAllowedMethods(Arrays.asList("HEAD", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList(
				"Accept", "Origin", "Content-Type", "Depth", "User-Agent", "If-Modified-Since,",
				"Cache-Control", "Authorization", "X-Req", "X-File-Size", "X-Requested-With", "X-File-Name"));

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

    @Bean
	public FilterRegistrationBean<CorsFilter> corsFilterRegistrationBean() {
		FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(corsConfigurationSource()));
		bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
		return bean;
	}
}
```

This will enable "Websecurity" on your Springboot webservice. The configuration will let GET request to /products pass through and will protect all other requests (including "/check").

We also implemented a custom "JWT decoder" in order to check user roles. In our case we will check whether a user has a "partner"-role.

Finally create a new "ScopeValidator.java" class and add the following code:

```
package com.example.Product;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

class ScopeValidator implements OAuth2TokenValidator<Jwt> {
  private final String scope;

  ScopeValidator(String scope) {
    Assert.hasText(scope, "scope is null or empty");
    this.scope = scope;
  }

  public OAuth2TokenValidatorResult validate(Jwt jwt) {
    String scopes = jwt.getClaims().get("scope").toString();
    System.out.println("Contains sequence 'partner': " + jwt.getClaims().get("scope").toString());
    System.out.println("Contains sequence 'partner': " + jwt.getClaims().get("scope").toString().contains("partner"));
    if (scopes.contains(this.scope)) {
      System.out.println("Successful ScopeValidator");
      return OAuth2TokenValidatorResult.success();
    }
    OAuth2Error err = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN);
    return OAuth2TokenValidatorResult.failure(err);
  }
}
```

This decoder will extract the "scope" from the JWT claims and check whether it contains "partner" value.

Now restart your Springboot application using the command: "mvn spring-boot:run"
Check you VueJS application again. After you login you should now see that you get an extra menu item "Register Product" when clicking on your username dropdown menu. Also check to make sure you don't see any errors in your Browser console.







