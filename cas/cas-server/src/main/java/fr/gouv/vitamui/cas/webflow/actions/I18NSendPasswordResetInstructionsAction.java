/**
 * Copyright French Prime minister Office/SGMAP/DINSIC/Vitam Program (2019-2020)
 * and the signatories of the "VITAM - Accord du Contributeur" agreement.
 *
 * contact@programmevitam.fr
 *
 * This software is a computer program whose purpose is to implement
 * implement a digital archiving front-office system for the secure and
 * efficient high volumetry VITAM solution.
 *
 * This software is governed by the CeCILL-C license under French law and
 * abiding by the rules of distribution of free software.  You can  use,
 * modify and/ or redistribute the software under the terms of the CeCILL-C
 * license as circulated by CEA, CNRS and INRIA at the following URL
 * "http://www.cecill.info".
 *
 * As a counterpart to the access to the source code and  rights to copy,
 * modify and redistribute granted by the license, users are provided only
 * with a limited warranty  and the software's author,  the holder of the
 * economic rights,  and the successive licensors  have only  limited
 * liability.
 *
 * In this respect, the user's attention is drawn to the risks associated
 * with loading,  using,  modifying and/or developing or reproducing the
 * software by the user in light of its specific status of free software,
 * that may mean  that it is complicated to manipulate,  and  that  also
 * therefore means  that it is reserved for developers  and  experienced
 * professionals having in-depth computer knowledge. Users are therefore
 * encouraged to load and test the software's suitability as regards their
 * requirements in conditions enabling the security of their systems and/or
 * data to be ensured and,  more generally, to use and operate it in the
 * same conditions as regards security.
 *
 * The fact that you are presently reading this means that you have had
 * knowledge of the CeCILL-C license and that you accept its terms.
 */
package fr.gouv.vitamui.cas.webflow.actions;

import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.audit.AuditActionResolvers;
import org.apereo.cas.audit.AuditResourceResolvers;
import org.apereo.cas.audit.AuditableActions;
import org.apereo.cas.authentication.credential.UsernamePasswordCredential;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.notifications.CommunicationsManager;
import org.apereo.cas.pm.PasswordManagementService;
import org.apereo.cas.pm.web.flow.actions.SendPasswordResetInstructionsAction;
import org.apereo.cas.ticket.TicketFactory;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.web.support.WebUtils;
import org.apereo.inspektr.audit.annotation.Audit;
import org.springframework.context.HierarchicalMessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.webflow.core.collection.MutableAttributeMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import fr.gouv.vitamui.cas.pm.PmMessageToSend;
import fr.gouv.vitamui.cas.pm.PmTransientSessionTicketExpirationPolicyBuilder;
import fr.gouv.vitamui.cas.provider.ProvidersService;
import fr.gouv.vitamui.cas.util.Utils;
import fr.gouv.vitamui.commons.api.logger.VitamUILogger;
import fr.gouv.vitamui.commons.api.logger.VitamUILoggerFactory;
import fr.gouv.vitamui.iam.common.utils.IdentityProviderHelper;
import lombok.val;

/**
 * Send reset password emails with i18n messages.
 *
 *
 */
public class I18NSendPasswordResetInstructionsAction extends SendPasswordResetInstructionsAction {

    private static final VitamUILogger LOGGER = VitamUILoggerFactory.getInstance(I18NSendPasswordResetInstructionsAction.class);

    private final HierarchicalMessageSource messageSource;

    private final ProvidersService providersService;

    private final IdentityProviderHelper identityProviderHelper;

    private final Utils utils;

    private final String vitamuiPlatformName;

    public I18NSendPasswordResetInstructionsAction(final CasConfigurationProperties casProperties,
                                                   final CommunicationsManager communicationsManager,
                                                   final PasswordManagementService passwordManagementService,
                                                   final TicketRegistry ticketRegistry,
                                                   final TicketFactory ticketFactory,
                                                   final HierarchicalMessageSource messageSource,
                                                   final ProvidersService providersService,
                                                   final IdentityProviderHelper identityProviderHelper,
                                                   final Utils utils,
                                                   final String vitamuiPlatformName) {
        super(casProperties, communicationsManager, passwordManagementService, ticketRegistry, ticketFactory, null);
        this.messageSource = messageSource;
        this.providersService = providersService;
        this.identityProviderHelper = identityProviderHelper;
        this.utils = utils;
        this.vitamuiPlatformName = vitamuiPlatformName;
    }

    @Audit(action = AuditableActions.REQUEST_CHANGE_PASSWORD,
        principalResolverName = "REQUEST_CHANGE_PASSWORD_PRINCIPAL_RESOLVER",
        actionResolverName = AuditActionResolvers.REQUEST_CHANGE_PASSWORD_ACTION_RESOLVER,
        resourceResolverName = AuditResourceResolvers.REQUEST_CHANGE_PASSWORD_RESOURCE_RESOLVER)
    @Override
    protected Event doExecute(final RequestContext requestContext) {
        if (!communicationsManager.isMailSenderDefined() && !communicationsManager.isSmsSenderDefined()) {
            return getErrorEvent("contact.failed", "Unable to send email as no mail sender is defined", requestContext);
        }

        // CUSTO: try to get the username from the credentials also (after a password expiration)
        val request = WebUtils.getHttpServletRequestFromExternalWebflowContext(requestContext);
        request.removeAttribute(PmTransientSessionTicketExpirationPolicyBuilder.PM_EXPIRATION_IN_MINUTES_ATTRIBUTE);
        String username = request.getParameter("username");
        if (StringUtils.isBlank(username)) {
            final MutableAttributeMap<Object> flowScope = requestContext.getFlowScope();
            final Object credential = flowScope.get("credential");
            if (credential instanceof UsernamePasswordCredential) {
                final UsernamePasswordCredential usernamePasswordCredential = (UsernamePasswordCredential) credential;
                username = usernamePasswordCredential.getUsername();
            }
        }
        val query = buildPasswordManagementQuery(requestContext);
        if (StringUtils.isBlank(username)) {
            return getErrorEvent("username.required", "No username is provided", requestContext);
        }

        val email = passwordManagementService.findEmail(query);
        // CUSTO: only retrieve email (and not phone) and force success event (instead of error) when failure
        if (StringUtils.isBlank(email)) {
            LOGGER.warn("No recipient is provided; nonetheless, we return to the success page");
            return success();
        } else if (!identityProviderHelper.identifierMatchProviderPattern(providersService.getProviders(), email)) {
            LOGGER.warn("Recipient: {} is not internal; ignoring and returning to the success page", email);
            return success();
        }

        val service = WebUtils.getService(requestContext);
        val url = buildPasswordResetUrl(query.getUsername(), passwordManagementService, casProperties, service);
        if (StringUtils.isNotBlank(url)) {
            val pm = casProperties.getAuthn().getPm();
            LOGGER.debug("Generated password reset URL [{}]; Link is only active for the next [{}] minute(s)",
                url, pm.getReset().getExpirationMinutes());
            // CUSTO: only send email (and not SMS)
            val sendEmail = sendPasswordResetEmailToAccount(query.getUsername(), email, url, requestContext);
            if (sendEmail) {
                return success(url);
            }
        } else {
            LOGGER.error("No password reset URL could be built and sent to [{}]", email);
        }
        LOGGER.error("Failed to notify account [{}]", email);
        return getErrorEvent("contact.failed", "Failed to send the password reset link via email address or phone", requestContext);
    }

    @Override
    protected boolean sendPasswordResetEmailToAccount(final String username, final String to, final String url,
                                                      final RequestContext requestContext) {
        final PmMessageToSend messageToSend = PmMessageToSend.buildMessage(messageSource, "", "",
            String.valueOf(casProperties.getAuthn().getPm().getReset().getExpirationMinutes()), url, vitamuiPlatformName,
            LocaleContextHolder.getLocale());
        return utils.htmlEmail(messageToSend.getText(), casProperties.getAuthn().getPm().getReset().getMail().getFrom(), messageToSend.getSubject(), to, null,
                null);
    }
}
