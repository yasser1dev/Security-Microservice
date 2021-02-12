package com.mss.authservice.demo.security.web;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.mss.authservice.demo.security.JWTUtils;
import com.mss.authservice.demo.security.dto.UserRoleModel;
import com.mss.authservice.demo.security.entities.AppRole;
import com.mss.authservice.demo.security.entities.AppUser;
import com.mss.authservice.demo.security.service.AccountService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AccountRestControllers {
    private AccountService accountService;

    public AccountRestControllers(AccountService accountService) {

        this.accountService = accountService;
    }


    @GetMapping(path = "/users")
    public List<AppUser> appUsers(){

        return accountService.listUsers();
    }

    @PostMapping(path = "/addUser")
    public AppUser addUser(@RequestBody AppUser user){

        return accountService.addNewUser(user);
    }

    @PostMapping(path = "/addRole")
    public AppRole addRole(@RequestBody AppRole role){

        return accountService.addNewRole(role);
    }

    @PostMapping(path = "/addRoleToUser")
    public void addRoleToUser(@RequestBody UserRoleModel userModel){
        accountService.addRoleToUser(userModel.getUser(),userModel.getRole());
    }

    @PostMapping(path = "/refreshToken")
    public Map<String,String> refreshToken(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String token=request.getHeader(JWTUtils.HEADER);
        if(token!=null || token.startsWith(JWTUtils.PREFIX)){
           try{ String jwtRefreshToken=token.substring(7);
                Algorithm algorithm=Algorithm.HMAC256(JWTUtils.SECRET);
                JWTVerifier jwtVerifier= JWT.require(algorithm).build();
                DecodedJWT decodedJWT=jwtVerifier.verify(jwtRefreshToken);
                String username=decodedJWT.getSubject();
                AppUser user=accountService.loadUserByUsername(username);
                String jwtAccessToken=JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+JWTUtils.DATE_EXP_ACCESS_TOKEN))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles",user.getAppRoles().
                                stream().map(e->e.getRole()).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String,String> accessToken=new HashMap<>();
                accessToken.put("Access_Token",jwtAccessToken);
                accessToken.put("Refrsh Token",jwtRefreshToken);
                return  accessToken;
           }catch (TokenExpiredException e){
               response.setHeader("Error msg",e.getMessage());
               response.sendError(HttpServletResponse.SC_FORBIDDEN);
           }
        }
        throw new RuntimeException("Bad refresh token");
    }


}
