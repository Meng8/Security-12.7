##Spring Security
*Spring Security是一个能够为基于Spring的企业应用系统提供声明式的安全访问控制解决方案的安全框架。主要作用是认证和授权，通过过滤器和拦截器做到安全访问控制的效果.*

> 选择协议：启动时，就加载全部权限
权限控制： **1.菜单， 2.方法， 3.页面按钮， 4.页面片段 新增用户**，不重启系统，ResultMap
分层 --domain:（Entity+Repository） --sevice --controller: WEB(get)+API(post及其他) --view

###依赖导入
> - 首先创建一个**Spring Starter project**项目  **jar**工程
  - 先导入**security**和**web**依赖，
  - 由于要用到thymeleaf所以要导入**thymeleaf**依赖，
  - css的样式要求也要导入**bootstrap**依赖。

###登陆控制
> 在src/main/java下创建一个类和Application相同目录下的（不然不一定能访问的到）
  
  - 使用默认的登录界面
  ```
  
	//设置内存认证
	@EnableWebSecurity
	public class WebSecurityConfig extends WebSecurityConfigurerAdapter{
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Throwable {
		//设置内存认证
		auth
		       .inMemoryAuthentication()
		 //设置用户名 密码 和 权限
		.withUser("root").password("root").roles("boss")
		//添加多个用户在后面.and()在用.就能调出来了
		       .and()
		.withUser("admin").password("admin").roles("bang");
		System.out.println("=====================");
	}
	
	//HttpSecurity：一般用它来具体控制权限，角色，url等安全的东西。
	protected void configure(HttpSecurity http) throws Exception {
		http
		.authorizeRequests()
     .antMatchers("/webjars/**", "/signup", "/about").permitAll()
		.antMatchers("/admin/**").hasRole("UADMINSER")
		.antMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')")
		.anyRequest().authenticated().and().formLogin()
		//设置跳转路径
		.loginPage("/login")
		//登陆成功后跳转的路径
		.permitAll()
		/*.successForwardUrl("/login")	*/
		.and().logout().and()
     .httpBasic();
		http.csrf().disable();//页面登陆报403错误时关闭csrf功能
		
		System.out.println("=111111111111111111");
	 }
    }
 ```
 
   **这里面设置跳转路径只能是login否则不会进行页面跳转**
         
   - loginController
         > Controller跳转login必须要用get方式提交，因为get只能查看数据库资源，可以通过CSRF保护机制，而post方式提交就涉及到可以修改数据库信息。CSRF保护机制就会拒绝访问。
         
  ```
	@Controller
	public class LoginController {
		@RequestMapping(value="login",method=RequestMethod.GET)
		public String login() {
			return "login";
		}
		//使用'/'路径，解决404错误。
	@RequestMapping(value="/",method=RequestMethod.GET)
		public String dosuccess() {
			return "index";
		}
	
	}
  ```    
  
  ###登陆界面
  - css的样式要求也要导入**bootstrap**依赖。pom.xml引入文件如下：
  ```
  
		  <dependency>
					<groupId>org.webjars</groupId>
					<artifactId>bootstrap</artifactId>
					<version>3.2.0</version>
		  </dependency>
  ```
  

  - 同样，以jar加入的静态文件，都位于webjars目录下。
            在未登录时，不显示样式，则需要配置application.properties，使其忽略，不要拦截bootstrap文件。
            
    
   ```
	security.ignored[0]=/css/*
	security.ignored[1]=/js/**
	security.ignored[2]=/images/*
	security.ignored[3]=/fonts/**
	security.ignored[4]=/**/favicon.ico
	security.ignored[5]=/**/**.png
	security.ignored[6]=webjars/**
  ```
	  - `server.port=9999`可以 修改访问该项目的端口号
	  - 这里的form表单路径只能写**action="login"**
	  
  ```
  
   <!DOCTYPE html >
<html xmlns:th="http://www.thymeleaf.org">
<head>
<title>Login</title>
<meta charset="UTF-8"></meta>
<link rel="stylesheet"
	th:href="@{/webjars/bootstrap/3.2.0/css/bootstrap.min.css}"
	href="/webjars/bootstrap/3.2.0/css/bootstrap.min.css" />
</head>
<style>
<!--
body {
	padding-top: 20px;
}
-->
</style>
<body onload="document.form.username.focus();">
	<nav class="navbar navbar-default" role="navigation">
		<div class="container-fluid">
			<div class="navbar-header">
				<a class="navbar-brand" href=" ">**系统登录</a>
			</div>
		</div>
	</nav>
	<div class="container">
		<div class="row">
			<div class="col-md-4 col-md-offset-4">
				<div class="panel panel-default">
					<div class="panel-heading">
						<h3 class="panel-title">Please sign in</h3>
					</div>
					<div class="panel-body">
						<form name="form" th:action="login" method="POST">
							<fieldset>
								<div class="form-group">
									<input class="form-control" placeholder="username"
										name="username" type="text" />
								</div>
								<div class="form-group">
									<input class="form-control" placeholder="Password"
										name="password" type="password" value="" />
								</div>
								<div class="checkbox">
									<label> <input name="remember" type="checkbox"
										value="Remember Me" /> Remember Me
									</label>
								</div>
								<input class="btn btn-lg btn-success btn-block" type="submit"
									value="Login" /> <input type="hidden"
									th:name="${_csrf.parameterName}" th:value="${_csrf.token}"
									th:if="${_csrf}" />
							</fieldset>
						</form>
						<div th:if="${session.SPRING_SECURITY_LAST_EXCEPTION!=null}">
						<div class="alert alert-danger alert-dismissable">
							<button type="button" class="close" data-dismiss="alert"
								aria-hidden="true">&times;</button>
							<span th:text="${session.SPRING_SECURITY_LAST_EXCEPTION.message}" ></span>
						</div>
						<input type="hidden" th:name="${_csrf.parameterName}"
							th:value="${_csrf.token}" th:if="${_csrf}" />
					</div>
					</div>
				</div>
			</div>
		</div>
	</div>

</body>
</html>
   ```
   
  
  
  > 注意： @EnableGlobalMethodSecurity 可以配置多个参数: prePostEnabled :决定SpringSecurity的前注解是否可用如：@PreAuthorize,@PostAuthorize secureEnabled : 决定是否Spring Security的保障注解 [@Secured] 是否可用 jsr250Enabled ：决定 JSR-250 annotations 注解[@RolesAllowed..] 是否可用.
  
  