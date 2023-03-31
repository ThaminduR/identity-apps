<%--
  ~ Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
  ~
  ~  WSO2 Inc. licenses this file to you under the Apache License,
  ~  Version 2.0 (the "License"); you may not use this file except
  ~  in compliance with the License.
  ~  You may obtain a copy of the License at
  ~
  ~    http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  --%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.apache.commons.lang.StringUtils" %>
<%@ page import="org.owasp.encoder.Encode" %>
<%@ page import="org.wso2.carbon.identity.captcha.util.CaptchaUtil" %>
<%@ page import="org.wso2.carbon.identity.mgt.endpoint.util.client.ApiException" %>
<%@ page import="org.wso2.carbon.identity.base.IdentityRuntimeException" %>
<%@ page import="org.wso2.carbon.identity.mgt.constants.SelfRegistrationStatusCodes" %>
<%@ page import="org.wso2.carbon.identity.mgt.endpoint.util.client.api.ReCaptchaApi" %>
<%@ page import="org.wso2.carbon.identity.mgt.endpoint.util.client.model.ReCaptchaProperties" %>
<%@ page import="org.wso2.carbon.identity.mgt.endpoint.util.IdentityManagementEndpointConstants" %>
<%@ page import="org.wso2.carbon.identity.mgt.endpoint.util.IdentityManagementEndpointUtil" %>
<%@ page import="org.wso2.carbon.identity.mgt.endpoint.util.IdentityManagementServiceUtil" %>
<%@ page import="org.wso2.carbon.identity.mgt.endpoint.util.client.model.User" %>
<%@ page import="org.wso2.carbon.identity.core.util.IdentityTenantUtil" %>
<%@ page import="java.util.Arrays" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="java.io.File" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.Map" %>

<jsp:directive.include file="includes/localize.jsp"/>
<jsp:directive.include file="tenant-resolve.jsp"/>

<%
    boolean error = IdentityManagementEndpointUtil.getBooleanValue(request.getAttribute("error"));
    boolean isSaaSApp = Boolean.parseBoolean(request.getParameter("isSaaSApp"));
    boolean skipSignUpEnableCheck = Boolean.parseBoolean(request.getParameter("skipsignupenablecheck"));
    String username = request.getParameter("username");
    User user = IdentityManagementServiceUtil.getInstance().resolveUser(username, tenantDomain, isSaaSApp);
    Object errorCodeObj = request.getAttribute("errorCode");
    Object errorMsgObj = request.getAttribute("errorMsg");
    String callback = Encode.forHtmlAttribute(request.getParameter("callback"));
    String errorCode = null;
    String errorMsg = null;

    if (errorCodeObj != null) {
        errorCode = errorCodeObj.toString();
    }
    if (SelfRegistrationStatusCodes.ERROR_CODE_INVALID_TENANT.equalsIgnoreCase(errorCode)) {
        errorMsg = "Invalid tenant domain - " + user.getTenantDomain();
    } else if (SelfRegistrationStatusCodes.ERROR_CODE_USER_ALREADY_EXISTS.equalsIgnoreCase(errorCode)) {
        errorMsg = "Username '" + username + "' is already taken. Please pick a different username";
    } else if (SelfRegistrationStatusCodes.ERROR_CODE_SELF_REGISTRATION_DISABLED.equalsIgnoreCase(errorCode)) {
        errorMsg = "Self registration is disabled for tenant - " + user.getTenantDomain();
    } else if (SelfRegistrationStatusCodes.CODE_USER_NAME_INVALID.equalsIgnoreCase(errorCode)) {
        errorMsg = user.getUsername() + " is an invalid user name. Please pick a valid username.";
    } else if (StringUtils.equalsIgnoreCase(SelfRegistrationStatusCodes.ERROR_CODE_INVALID_EMAIL_USERNAME,
            errorCode)) {
        errorMsg = "Username is invalid. Username should be in email format.";
    } else if (errorMsgObj != null) {
        errorMsg = errorMsgObj.toString();
    }

    ReCaptchaApi reCaptchaApi = new ReCaptchaApi();
        try {
            ReCaptchaProperties reCaptchaProperties = null;
            if (request.getParameter("tenantDomain") == null && user != null && StringUtils.isNotEmpty(user.getTenantDomain())) {
                try {
                    IdentityTenantUtil.getTenantId(user.getTenantDomain());
                    reCaptchaProperties = reCaptchaApi.getReCaptcha(user.getTenantDomain(), true, "ReCaptcha", "self-registration");
                } catch (IdentityRuntimeException e) {
                    request.setAttribute("error", true);
                    request.setAttribute("errorMsg", e.getMessage());
                    request.getRequestDispatcher("error.jsp").forward(request, response);
                    return;
                }
            } else if (request.getParameter("tenantDomain") != null ) {
                reCaptchaProperties = reCaptchaApi.getReCaptcha(tenantDomain, true, "ReCaptcha", "self-registration");
            }
            if (reCaptchaProperties != null && reCaptchaProperties.getReCaptchaEnabled()) {
                Map<String, List<String>> headers = new HashMap<>();
                headers.put("reCaptcha", Arrays.asList(String.valueOf(true)));
                headers.put("reCaptchaAPI", Arrays.asList(reCaptchaProperties.getReCaptchaAPI()));
                headers.put("reCaptchaKey", Arrays.asList(reCaptchaProperties.getReCaptchaKey()));
                IdentityManagementEndpointUtil.addReCaptchaHeaders(request, headers);
            }
        } catch (ApiException e) {
            IdentityManagementEndpointUtil.addErrorInformation(request, e);
            request.getRequestDispatcher("error.jsp").forward(request, response);
            return;
        }
    %>

    <%
        boolean reCaptchaEnabled = false;
        if (request.getAttribute("reCaptcha") != null && "TRUE".equalsIgnoreCase((String) request.getAttribute("reCaptcha"))) {
            reCaptchaEnabled = true;
        } else if (request.getParameter("reCaptcha") != null && Boolean.parseBoolean(request.getParameter("reCaptcha"))) {
            reCaptchaEnabled = true;
        }
%>

<!doctype html>
<html>
<head>
    <!-- header -->
    <%
        File headerFile = new File(getServletContext().getRealPath("extensions/header.jsp"));
        if (headerFile.exists()) {
    %>
    <jsp:include page="extensions/header.jsp"/>
    <% } else { %>
    <jsp:include page="includes/header.jsp"/>
    <% } %>
        <%
            if (reCaptchaEnabled) {
                String reCaptchaAPI = CaptchaUtil.reCaptchaAPIURL();
        %>
        <script src='<%=(reCaptchaAPI)%>'></script>
        <%
           }
        %>
</head>
<body class="login-portal layout recovery-layout">
    <main class="center-segment">
        <div class="ui container medium center aligned middle aligned">
            <!-- product-title -->
            <%
                File productTitleFile = new File(getServletContext().getRealPath("extensions/product-title.jsp"));
                if (productTitleFile.exists()) {
            %>
            <jsp:include page="extensions/product-title.jsp"/>
            <% } else { %>
            <jsp:include page="includes/product-title.jsp"/>
            <% } %>
            <div class="ui segment">
                <h3 class="ui header">
                    <%=IdentityManagementEndpointUtil.i18n(recoveryResourceBundle, "Start.signing.up")%>
                </h3>

                <div class="ui negative message" id="error-msg" hidden="hidden"></div>
                <% if (error) { %>
                <div class="ui negative message" id="server-error-msg">
                    <%= IdentityManagementEndpointUtil.i18nBase64(recoveryResourceBundle, errorMsg) %>
                </div>
                <% } %>
                <!-- validation -->

                <div class="ui divider hidden"></div>
                <div class="segment-form">
                    <form class="ui large form" action="signup.do" method="post" id="register">

                        <div class="field">
                            <label for="username">
                                <%=IdentityManagementEndpointUtil.i18n(recoveryResourceBundle,
                                    "Enter.your.username.here")%>
                            </label>
                            <input id="usernameUserInput" name="usernameUserInput" type="text" required>
                            <input id="username" name="username" type="hidden"
                                <% if(skipSignUpEnableCheck) {%> value="<%=Encode.forHtmlAttribute(username)%>" <%}%>>
                        </div>

                        <% if (isSaaSApp) { %>
                        <p class="ui tiny compact info message">
                            <i class="icon info circle"></i>
                            <%=IdentityManagementEndpointUtil.i18n(recoveryResourceBundle,
                                    "If.you.specify.tenant.domain.you.registered.under.super.tenant")%>
                        </p>
                        <% } %>

                        <input id="callback" name="callback" type="hidden" value="<%=callback%>"
                               class="form-control" required>

                        <% Map<String, String[]> requestMap = request.getParameterMap();
                            for (Map.Entry<String, String[]> entry : requestMap.entrySet()) {
                                String key = Encode.forHtmlAttribute(entry.getKey());
                                String value = Encode.forHtmlAttribute(entry.getValue()[0]);
                                if (StringUtils.equalsIgnoreCase("reCaptcha", key)) {
                                    continue;
                                } %>
                        <div class="field">
                            <input id="<%= key%>" name="<%= key%>" type="hidden"
                                   value="<%=value%>" class="form-control">
                        </div>
                        <% } %>
                        <div class="field">
                            <%
                                if (reCaptchaEnabled) {
                                    String reCaptchaKey = CaptchaUtil.reCaptchaSiteKey();
                            %>
                            <div class="field">
                                <div class="g-recaptcha"
                                    data-sitekey="<%=Encode.forHtmlContent(reCaptchaKey)%>">
                                </div>
                            </div>
                            <%
                                }
                            %>
                        <div class="ui divider hidden"></div>

                        <div class="align-right buttons">
                            <a href="javascript:goBack()" class="ui button link-button">
                                <%=IdentityManagementEndpointUtil.i18n(recoveryResourceBundle, "Cancel")%>
                            </a>
                            <button id="registrationSubmit" class="ui primary button" type="submit">
                                <%=IdentityManagementEndpointUtil.i18n(recoveryResourceBundle,
                                        "Proceed.to.self.register")%>
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </main>
    <!-- product-footer -->
    <%
        File productFooterFile = new File(getServletContext().getRealPath("extensions/product-footer.jsp"));
        if (productFooterFile.exists()) {
    %>
    <jsp:include page="extensions/product-footer.jsp"/>
    <% } else { %>
    <jsp:include page="includes/product-footer.jsp"/>
    <% } %>

    <!-- footer -->
    <%
        File footerFile = new File(getServletContext().getRealPath("extensions/footer.jsp"));
        if (footerFile.exists()) {
    %>
    <jsp:include page="extensions/footer.jsp"/>
    <% } else { %>
    <jsp:include page="includes/footer.jsp"/>
    <% } %>

    <script>
        var $registerForm = $("#register");

        // Reloads the page if the page is loaded by going back in history.
        // Fixes issues with Firefox.
        window.addEventListener( "pageshow", function ( event ) {
            var historyTraversal = event.persisted ||
                                ( typeof window.performance != "undefined" &&
                                    window.performance.navigation.type === 2 );

            if ( historyTraversal ) {
                if($registerForm){
                    $registerForm.data("submitted", false);
                }
            }
        });

        function goBack() {
            window.history.back();
        }

        // Handle form submission preventing double submission.
        $(document).ready(function(){
            $.fn.preventDoubleSubmission = function() {
                $(this).on("submit", function(e){
                    var $form = $(this);

                    if ($form.data("submitted") === true) {
                        // Previously submitted - don't submit again.
                        e.preventDefault();
                        console.warn("Prevented a possible double submit event");
                    } else {
                        e.preventDefault();
                           <%
                                if(reCaptchaEnabled) {
                           %>
                           var resp = $("[name='g-recaptcha-response']")[0].value;
                           if (resp.trim() == '') {
                                $("#server-error-msg").remove();
                                error_msg.text("<%=IdentityManagementEndpointUtil.i18n(recoveryResourceBundle,
                                    "Please.select.reCaptcha")%>");
                                error_msg.show();
                                $("html, body").animate({scrollTop: error_msg.offset().top}, 'slow');
                                return false;
                           }
                           <%
                                }
                           %>

                        var userName = document.getElementById("username");
                        var usernameUserInput = document.getElementById("usernameUserInput");

                        if (usernameUserInput) {
                            userName.value = usernameUserInput.value.trim();
                        }

                        // Mark it so that the next submit can be ignored.
                        $form.data("submitted", true);
                        document.getElementById("register").submit();
                    }
                });

                return this;
            };

            $registerForm.preventDoubleSubmission();
        });
    </script>

</body>
</html>
