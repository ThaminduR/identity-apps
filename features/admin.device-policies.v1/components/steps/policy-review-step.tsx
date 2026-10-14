/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import { Theme, styled } from "@mui/material/styles";
import Alert from "@oxygen-ui/react/Alert";
import AlertTitle from "@oxygen-ui/react/AlertTitle";
import Box from "@oxygen-ui/react/Box";
import Button from "@oxygen-ui/react/Button";
import Card from "@oxygen-ui/react/Card";
import Chip from "@oxygen-ui/react/Chip";
import List from "@oxygen-ui/react/List";
import ListItem from "@oxygen-ui/react/ListItem";
import Stack from "@oxygen-ui/react/Stack";
import Typography from "@oxygen-ui/react/Typography";
import {
    ConditionExpressionWithoutIdInterface,
    RuleConditionWithoutIdInterface,
    RuleWithoutIdInterface
} from "@wso2is/admin.rules.v1/models/rules";
import { IdentifiableComponentInterface } from "@wso2is/core/models";
import React, { Fragment, FunctionComponent, ReactElement } from "react";
import { Trans, useTranslation } from "react-i18next";
import { DevicePlatformType, PlatformDefinitionInterface } from "../../models/device-policy";
import { countConditions } from "../../utils/device-policy-rule-utils";

const SectionHeader: typeof Stack = styled(Stack)(({ theme }: { theme: Theme }) => ({
    alignItems: "baseline",
    flexDirection: "row",
    justifyContent: "space-between",
    marginBottom: theme.spacing(1.5)
}));

const SectionTitle: typeof Typography = styled(Typography)(({ theme }: { theme: Theme }) => ({
    color: theme.palette.text.secondary,
    fontWeight: theme.typography.fontWeightBold,
    letterSpacing: "0.06em"
}));

const SummaryGrid: typeof Box = styled(Box)(({ theme }: { theme: Theme }) => ({
    columnGap: theme.spacing(2.5),
    display: "grid",
    gridTemplateColumns: `${ theme.spacing(20) } 1fr`,
    marginBottom: theme.spacing(3.5),
    rowGap: theme.spacing(1.75)
}));

const SummaryLabel: typeof Typography = styled(Typography)(({ theme }: { theme: Theme }) => ({
    color: theme.palette.text.secondary,
    fontWeight: theme.typography.fontWeightMedium,
    paddingTop: theme.spacing(0.5)
}));

const SummaryValue: typeof Typography = styled(Typography)(({ theme }: { theme: Theme }) => ({
    fontWeight: theme.typography.fontWeightMedium
}));

const PlaceholderText: typeof Typography = styled(Typography)(({ theme }: { theme: Theme }) => ({
    color: theme.palette.text.disabled
}));

const PlatformRuleCard: typeof Card = styled(Card)(({ theme }: { theme: Theme }) => ({
    marginBottom: theme.spacing(2),
    padding: theme.spacing(2.25)
}));

const PlatformRuleHeader: typeof Stack = styled(Stack)(({ theme }: { theme: Theme }) => ({
    alignItems: "center",
    flexDirection: "row",
    justifyContent: "space-between",
    marginBottom: theme.spacing(1.25)
}));

const PlatformChip: typeof Chip = styled(Chip)(({ theme }: { theme: Theme }) => ({
    borderColor: theme.palette.divider,
    color: theme.palette.text.secondary
}));

const RuleExpressionBlock: typeof Box = styled(Box)(({ theme }: { theme: Theme }) => ({
    backgroundColor: theme.palette.action.hover,
    borderRadius: theme.shape.borderRadius,
    fontFamily: "ui-monospace, \"SFMono-Regular\", Menlo, monospace",
    fontSize: theme.typography.body2.fontSize,
    lineHeight: 1.8,
    padding: theme.spacing(1.75)
}));

const RuleGroupSeparator: typeof Box = styled(Box)(({ theme }: { theme: Theme }) => ({
    color: theme.palette.primary.main,
    fontWeight: theme.typography.fontWeightBold,
    marginBottom: theme.spacing(0.75),
    marginTop: theme.spacing(0.75)
}));

const InlineText: typeof Typography = styled(Typography)({
    fontFamily: "inherit",
    fontSize: "inherit"
});

const ConjunctionText: typeof Typography = styled(InlineText)(({ theme }: { theme: Theme }) => ({
    color: theme.palette.text.secondary,
    fontWeight: theme.typography.fontWeightBold
}));

const FieldText: typeof Typography = styled(InlineText)(({ theme }: { theme: Theme }) => ({
    fontWeight: theme.typography.fontWeightMedium
}));

const OperatorText: typeof Typography = styled(InlineText)(({ theme }: { theme: Theme }) => ({
    color: theme.palette.text.secondary
}));

const ValueText: typeof Typography = styled(InlineText)(({ theme }: { theme: Theme }) => ({
    color: theme.palette.primary.main,
    fontWeight: theme.typography.fontWeightMedium
}));

const AssignHintList: typeof List = styled(List)(({ theme }: { theme: Theme }) => ({
    listStyleType: "disc",
    paddingBottom: 0,
    paddingLeft: theme.spacing(2.5),
    paddingTop: theme.spacing(0.5)
}));

const AssignHintListItem: typeof ListItem = styled(ListItem)({
    display: "list-item",
    padding: 0
});

interface PolicyReviewStepPropsInterface extends IdentifiableComponentInterface {
    platforms: PlatformDefinitionInterface[];
    selectedPlatforms: DevicePlatformType[];
    policyName: string;
    platformRules: Partial<Record<DevicePlatformType, RuleWithoutIdInterface | null>>;
    platformConfigured: Partial<Record<DevicePlatformType, boolean>>;
    /** Per-platform field-id → displayName map built from metadata. Fallback to raw id when absent. */
    fieldDisplayMap?: Partial<Record<DevicePlatformType, Map<string, string>>>;
    onEditPolicy?: () => void;
    onEditRules: () => void;
    showAssignHint?: boolean;
}

/**
 * Shared "Review" step for the device policy create/edit wizards.
 * Summarizes the policy name, selected platforms and per-platform rules.
 *
 * @param props - Props injected to the component.
 * @returns PolicyReviewStep component.
 */
const PolicyReviewStep: FunctionComponent<PolicyReviewStepPropsInterface> = (
    props: PolicyReviewStepPropsInterface
): ReactElement => {
    const {
        "data-componentid": componentId = "policy-review-step",
        platforms,
        selectedPlatforms,
        policyName,
        platformRules,
        platformConfigured,
        fieldDisplayMap,
        onEditPolicy,
        onEditRules,
        showAssignHint
    } = props;

    const { t } = useTranslation();

    const selectedPlatformDefs: PlatformDefinitionInterface[] = platforms.filter(
        (platform: PlatformDefinitionInterface) => selectedPlatforms.includes(platform.key)
    );

    const renderExpression = (
        platform: DevicePlatformType,
        expression: ConditionExpressionWithoutIdInterface,
        index: number
    ): ReactElement => (
        <span key={ index }>
            { index > 0 && (
                <ConjunctionText component="span">
                    { ` ${ t("devices:assurancePolicies.wizard.steps.review.and") } ` }
                </ConjunctionText>
            ) }
            <FieldText component="span">
                { fieldDisplayMap?.[platform]?.get(expression.field) ?? expression.field }
            </FieldText>
            <OperatorText component="span">
                { ` ${ expression.operator } ` }
            </OperatorText>
            <ValueText component="span">
                &ldquo;{ expression.value || "?" }&rdquo;
            </ValueText>
        </span>
    );

    const renderPlatformRule = (platform: PlatformDefinitionInterface): ReactElement => {
        const rule: RuleWithoutIdInterface | null | undefined = platformRules[platform.key];
        const isConfigured: boolean = platformConfigured[platform.key] === true;
        const conditionCount: number = isConfigured && rule ? countConditions(rule) : 0;
        const groupCount: number = isConfigured && rule ? (rule.rules?.length ?? 0) : 0;

        return (
            <PlatformRuleCard
                variant="outlined"
                key={ platform.key }
                data-componentid={ `${ componentId }-${ platform.key }-rule` }
            >
                <PlatformRuleHeader>
                    <PlatformChip label={ platform.label } size="small" variant="outlined" />
                    <Typography variant="caption" color="text.secondary">
                        { isConfigured
                            ? t("devices:assurancePolicies.wizard.steps.review.conditionCount", {
                                count: conditionCount,
                                groups: groupCount
                            })
                            : t("devices:assurancePolicies.wizard.steps.review.appliesToAll", {
                                platform: platform.label
                            })
                        }
                    </Typography>
                </PlatformRuleHeader>
                { isConfigured && rule && (
                    <RuleExpressionBlock>
                        { (rule.rules ?? []).map(
                            (group: RuleConditionWithoutIdInterface, groupIndex: number): ReactElement => (
                                <Fragment key={ groupIndex }>
                                    { groupIndex > 0 && (
                                        <RuleGroupSeparator>
                                            { t("devices:assurancePolicies.wizard.steps.review.or") }
                                        </RuleGroupSeparator>
                                    ) }
                                    <Box>
                                        (
                                        { (group.expressions ?? []).map(
                                            (
                                                expression: ConditionExpressionWithoutIdInterface,
                                                expressionIndex: number
                                            ): ReactElement =>
                                                renderExpression(platform.key, expression, expressionIndex)
                                        ) }
                                        )
                                    </Box>
                                </Fragment>
                            )
                        ) }
                    </RuleExpressionBlock>
                ) }
            </PlatformRuleCard>
        );
    };

    return (
        <Box data-componentid={ componentId }>
            <SectionHeader>
                <SectionTitle variant="overline">
                    { t("devices:assurancePolicies.wizard.steps.review.sectionPolicy") }
                </SectionTitle>
                { onEditPolicy && (
                    <Button
                        variant="text"
                        color="primary"
                        size="small"
                        onClick={ onEditPolicy }
                        data-componentid={ `${ componentId }-edit-policy-button` }
                    >
                        { t("devices:assurancePolicies.wizard.steps.review.edit") }
                    </Button>
                ) }
            </SectionHeader>
            <SummaryGrid>
                <SummaryLabel variant="body2">
                    { t("devices:assurancePolicies.wizard.steps.review.policyName") }
                </SummaryLabel>
                { policyName
                    ? <SummaryValue variant="body1">{ policyName }</SummaryValue>
                    : (
                        <PlaceholderText variant="body1">
                            { t("devices:assurancePolicies.wizard.steps.review.notSet") }
                        </PlaceholderText>
                    )
                }
                <SummaryLabel variant="body2">
                    { t("devices:assurancePolicies.wizard.steps.review.platforms") }
                </SummaryLabel>
                <Stack direction="row" spacing={ 1 } flexWrap="wrap" useFlexGap>
                    { selectedPlatformDefs.map((platform: PlatformDefinitionInterface) => (
                        <Chip
                            key={ platform.key }
                            label={ platform.label }
                            size="small"
                            color="primary"
                            variant="outlined"
                        />
                    )) }
                </Stack>
            </SummaryGrid>

            <SectionHeader>
                <SectionTitle variant="overline">
                    { t("devices:assurancePolicies.wizard.steps.review.sectionRules") }
                </SectionTitle>
                <Button
                    variant="text"
                    color="primary"
                    size="small"
                    onClick={ onEditRules }
                    data-componentid={ `${ componentId }-edit-rules-button` }
                >
                    { t("devices:assurancePolicies.wizard.steps.review.edit") }
                </Button>
            </SectionHeader>

            { selectedPlatformDefs.map(renderPlatformRule) }

            { showAssignHint && (
                <Alert severity="info" sx={ { mt: 3 } } data-componentid={ `${ componentId }-assign-hint` }>
                    <AlertTitle>
                        { t("devices:assurancePolicies.wizard.steps.review.assignHint.title") }
                    </AlertTitle>
                    <AssignHintList dense disablePadding>
                        <AssignHintListItem>
                            <Trans
                                i18nKey="devices:assurancePolicies.wizard.steps.review.assignHint.loginFlow"
                                components={ { strong: <strong /> } }
                            />
                        </AssignHintListItem>
                        <AssignHintListItem>
                            <Trans
                                i18nKey="devices:assurancePolicies.wizard.steps.review.assignHint.otherFlows"
                                components={ { strong: <strong /> } }
                            />
                        </AssignHintListItem>
                    </AssignHintList>
                </Alert>
            ) }
        </Box>
    );
};

export default PolicyReviewStep;
