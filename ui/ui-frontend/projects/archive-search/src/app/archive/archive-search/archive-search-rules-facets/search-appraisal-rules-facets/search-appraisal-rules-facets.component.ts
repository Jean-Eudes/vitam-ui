import { DatePipe } from '@angular/common';
import { Component, Input, OnChanges, OnInit } from '@angular/core';
import { TranslateService } from '@ngx-translate/core';
import { Colors } from 'ui-frontend-common';
import { FacetDetails } from 'ui-frontend-common/app/modules/models/operation/facet-details.interface';
import { RuleFacets } from '../../../models/search.criteria';

@Component({
  selector: 'app-search-appraisal-rules-facets',
  templateUrl: './search-appraisal-rules-facets.component.html',
  styleUrls: ['./search-appraisal-rules-facets.component.scss'],
})
export class SearchAppraisalRulesFacetsComponent implements OnInit, OnChanges {
  constructor(private translateService: TranslateService, private datePipe: DatePipe) {}

  @Input()
  appraisalRuleFacets: RuleFacets;

  @Input()
  totalResults: number;

  dateFilterValue: string;
  rulesFacetDetails: FacetDetails[] = [];
  expiredRulesFacetDetails: FacetDetails[] = [];
  finalActionFacetDetails: FacetDetails[] = [];
  archiveUnitsCountFacetDetails: FacetDetails[] = [];
  finalActionsFacetsValues: Map<string, number>;

  ngOnInit(): void {}
  ngOnChanges(): void {
    this.finalActionsFacetsValues = new Map();
    this.rulesFacetDetails = [];
    this.expiredRulesFacetDetails = [];
    this.finalActionFacetDetails = [];
    this.archiveUnitsCountFacetDetails = [];
    if (this.appraisalRuleFacets) {
      this.handleWaitingToRecalculateRulesFacets();
      this.handleFinalActionsRulesFacets();
      this.handleRulesDisctinctsFacets();
      this.handleRulesExpirationFacets();
    }
  }

  private handleRulesExpirationFacets() {
    let unexpiredRulesNb = 0;
    let expiredRulesNb = 0;
    this.dateFilterValue = this.datePipe.transform(new Date(), 'dd-MM-yyyy');

    if (this.appraisalRuleFacets.expiredRulesListFacets && this.appraisalRuleFacets.expiredRulesListFacets.length > 0) {
      this.appraisalRuleFacets.expiredRulesListFacets.forEach((elt) => {
        if (elt.node === 'UNEXPIRED') {
          unexpiredRulesNb = elt.count ? elt.count : 0;
        } else if (elt && elt.node && elt.node.length > 10) {
          this.dateFilterValue = ' ' + elt.node.substring(elt.node.length - 10, elt.node.length);
          expiredRulesNb = elt.count ? elt.count : 0;
        }
      });
    }

    this.expiredRulesFacetDetails.push({
      title: this.translateService.instant('ARCHIVE_SEARCH.FACETS.APPRAISAL_RULE.EXPIRED'),
      totalResults: expiredRulesNb,
      clickable: false,
      color: 'gray',
      filter: '>' + this.dateFilterValue,
      backgroundColor: Colors.DISABLED,
    });

    this.expiredRulesFacetDetails.push({
      title: this.translateService.instant('ARCHIVE_SEARCH.FACETS.APPRAISAL_RULE.NOT_EXPIRED'),
      totalResults: unexpiredRulesNb,
      clickable: false,
      color: 'gray',
      filter: '<' + this.dateFilterValue,
      backgroundColor: Colors.DISABLED,
    });
  }

  private handleRulesDisctinctsFacets() {
    if (this.appraisalRuleFacets.rulesListFacets && this.appraisalRuleFacets.rulesListFacets.length > 0) {
      this.rulesFacetDetails.push({
        title: this.translateService.instant('ARCHIVE_SEARCH.FACETS.APPRAISAL_RULE.DISTINCT_RULES'),
        totalResults: this.appraisalRuleFacets.rulesListFacets.length,
        clickable: false,
        color: 'gray',
        backgroundColor: Colors.DISABLED,
      });
    } else {
      this.rulesFacetDetails.push({
        title: this.translateService.instant('ARCHIVE_SEARCH.FACETS.APPRAISAL_RULE.DISTINCT_RULES'),
        totalResults: 0,
        clickable: false,
        color: 'gray',
        backgroundColor: Colors.DISABLED,
      });
    }
  }

  private handleFinalActionsRulesFacets() {
    this.finalActionsFacetsValues.set('KEEP', 0);
    this.finalActionsFacetsValues.set('DESTROY', 0);
    this.finalActionsFacetsValues.set('CONFLICT', 0);

    if (this.appraisalRuleFacets.finalActionsFacets) {
      this.appraisalRuleFacets.finalActionsFacets.forEach((elt) => {
        this.finalActionsFacetsValues.set(elt.node.toUpperCase(), elt.count ? elt.count : 0);
      });
    }

    this.finalActionFacetDetails.push({
      title: this.translateService.instant('ARCHIVE_SEARCH.FACETS.APPRAISAL_RULE.KEEP'),
      totalResults: this.finalActionsFacetsValues.get('KEEP'),
      clickable: false,
      color: 'green',
      filter: 'KEEP',
      backgroundColor: Colors.DISABLED,
    });

    this.finalActionFacetDetails.push({
      title: this.translateService.instant('ARCHIVE_SEARCH.FACETS.APPRAISAL_RULE.DESTROY'),
      totalResults: this.finalActionsFacetsValues.get('DESTROY'),
      clickable: false,
      color: 'orange',
      filter: 'DESTROY',
      backgroundColor: Colors.DISABLED,
    });

    this.finalActionFacetDetails.push({
      title: this.translateService.instant('ARCHIVE_SEARCH.FACETS.APPRAISAL_RULE.CONFLICT'),
      totalResults: this.finalActionsFacetsValues.get('CONFLICT'),
      clickable: false,
      color: 'red',
      filter: 'CONFLICT',
      backgroundColor: Colors.DISABLED,
    });
  }

  private handleWaitingToRecalculateRulesFacets() {
    if (
      this.appraisalRuleFacets.waitingToRecalculateRulesListFacets &&
      this.appraisalRuleFacets.waitingToRecalculateRulesListFacets.length > 0
    ) {
      this.appraisalRuleFacets.waitingToRecalculateRulesListFacets
        .filter((elt) => elt.node === 'true')
        .forEach((elt) => {
          let calculatedCount = elt.count ? elt.count : 0;
          let notCalculatedCount = this.totalResults - calculatedCount;
          this.archiveUnitsCountFacetDetails.push({
            title: this.translateService.instant('ARCHIVE_SEARCH.FACETS.APPRAISAL_RULE.WAITING_TO_RECALCULATE'),
            totalResults: notCalculatedCount,
            clickable: false,
            color: notCalculatedCount === 0 ? 'gray' : 'orange',
            backgroundColor: Colors.DISABLED,
          });
          this.archiveUnitsCountFacetDetails.push({
            title: this.translateService.instant('ARCHIVE_SEARCH.FACETS.APPRAISAL_RULE.CALCULATED'),
            totalResults: calculatedCount,
            clickable: false,
            color: 'gray',
            backgroundColor: Colors.DISABLED,
          });
        });
    } else {
      this.archiveUnitsCountFacetDetails.push({
        title: this.translateService.instant('ARCHIVE_SEARCH.FACETS.APPRAISAL_RULE.WAITING_TO_RECALCULATE'),
        totalResults: this.totalResults,
        clickable: false,
        color: this.totalResults === 0 ? 'gray' : 'orange',
        backgroundColor: Colors.DISABLED,
      });
      this.archiveUnitsCountFacetDetails.push({
        title: this.translateService.instant('ARCHIVE_SEARCH.FACETS.APPRAISAL_RULE.CALCULATED'),
        totalResults: 0,
        clickable: false,
        color: 'gray',
        backgroundColor: Colors.DISABLED,
      });
    }

    if (this.appraisalRuleFacets.noRulesFacets && this.appraisalRuleFacets.noRulesFacets.length > 0) {
      this.appraisalRuleFacets.noRulesFacets.forEach((elt) => {
        this.archiveUnitsCountFacetDetails.push({
          title: this.translateService.instant('ARCHIVE_SEARCH.FACETS.APPRAISAL_RULE.WITHOUT_RULES'),
          totalResults: elt.count ? elt.count : 0,
          clickable: false,
          color: 'gray',
          backgroundColor: Colors.DISABLED,
        });
      });
    } else {
      this.archiveUnitsCountFacetDetails.push({
        title: this.translateService.instant('ARCHIVE_SEARCH.FACETS.APPRAISAL_RULE.WITHOUT_RULES'),
        totalResults: 0,
        clickable: false,
        color: 'gray',
        backgroundColor: Colors.DISABLED,
      });
    }
  }
}
