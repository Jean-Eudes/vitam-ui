/*
 * Copyright French Prime minister Office/SGMAP/DINSIC/Vitam Program (2015-2022)
 *
 * contact.vitam@culture.gouv.fr
 *
 * This software is a computer program whose purpose is to implement a digital archiving back-office system managing
 * high volumetry securely and efficiently.
 *
 * This software is governed by the CeCILL 2.1 license under French law and abiding by the rules of distribution of free
 * software. You can use, modify and/ or redistribute the software under the terms of the CeCILL 2.1 license as
 * circulated by CEA, CNRS and INRIA at the following URL "https://cecill.info".
 *
 * As a counterpart to the access to the source code and rights to copy, modify and redistribute granted by the license,
 * users are provided only with a limited warranty and the software's author, the holder of the economic rights, and the
 * successive licensors have only limited liability.
 *
 * In this respect, the user's attention is drawn to the risks associated with loading, using, modifying and/or
 * developing or reproducing the software by the user in light of its specific status of free software, that may mean
 * that it is complicated to manipulate, and that also therefore means that it is reserved for developers and
 * experienced professionals having in-depth computer knowledge. Users are therefore encouraged to load and test the
 * software's suitability as regards their requirements in conditions enabling the security of their systems and/or data
 * to be ensured and, more generally, to use and operate it in the same conditions as regards security.
 *
 * The fact that you are presently reading this means that you have had knowledge of the CeCILL 2.1 license and that you
 * accept its terms.
 */

package fr.gouv.vitamui.collect.internal.server.service;

import fr.gouv.vitam.collect.external.client.CollectClient;
import fr.gouv.vitam.common.client.VitamContext;
import fr.gouv.vitamui.collect.common.dto.ProjectDto;
import fr.gouv.vitamui.commons.api.domain.DirectionDto;
import fr.gouv.vitamui.commons.api.domain.PaginatedValuesDto;
import fr.gouv.vitamui.commons.api.logger.VitamUILogger;
import fr.gouv.vitamui.commons.api.logger.VitamUILoggerFactory;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class CollectInternalService {

    private final CollectClient collectClient;
    private static final VitamUILogger LOGGER = VitamUILoggerFactory.getInstance(CollectInternalService.class);

    public CollectInternalService(CollectClient collectClient) {
        this.collectClient = collectClient;
    }

    public ProjectDto createProject(VitamContext vitamContext, ProjectDto projectDto) {
        // TODO: Données de mock, à remplacer avec l'appel vers le client VITAM
        return ProjectDto.builder()
            .id("COLLECT_" + OffsetDateTime.now().format(DateTimeFormatter.ofPattern("yyyy_MM_dd_HH_mm_ss")))
            .archivalAgreement("IC00001")
            .messageIdentifier("MessageIdentifier")
            .archivalAgencyIdentifier("ArchivalAgencyIdentifier4")
            .originatingAgencyIdentifier("FRAN_NP_009913")
            .submissionAgencyIdentifier("SubmissionAgencyIdentifier")
            .transferringAgencyIdentifier("TransferringAgencyIdentifier5")
            .archivalProfile("ArchiveProfile")
            .comment("Commentaire")
            .status("OPEN")
            .build();
    }

    public PaginatedValuesDto<ProjectDto> getAllProjectsPaginated(VitamContext vitamContext, Integer page, Integer size,
        Optional<String> orderBy, Optional<DirectionDto> direction, Optional<String> criteria) {
        // TODO: Données de mock, à remplacer avec l'appel vers le client VITAM
        List<ProjectDto> projects = IntStream.range(0, 10).boxed()
            .map(index -> ProjectDto.builder()
                .archivalAgreement("IC0000" + index)
                .messageIdentifier("MessageIdentifier" + index)
                .archivalAgencyIdentifier("ArchivalAgencyIdentifier" + index)
                .originatingAgencyIdentifier("FRAN_NP_009913")
                .submissionAgencyIdentifier("SubmissionAgencyIdentifier" + index)
                .transferringAgencyIdentifier("TransferringAgencyIdentifier" + index)
                .archivalProfile("ArchiveProfile" + index)
                .comment("Commentaire")
                .status("OPEN")
                .createdOn(OffsetDateTime.now())
                .lastModifyOn(OffsetDateTime.now())
                .build()
            ).collect(Collectors.toList());
        return new PaginatedValuesDto<>(projects, 1, 20, false);
    }

    public ProjectDto update(String id, ProjectDto projectDto) {
        // TODO: Données de mock, à remplacer avec l'appel vers le client VITAM
        LOGGER.debug("id : {}", id);
        LOGGER.debug("projectDto : {}", projectDto);
        return projectDto;
    }
}
