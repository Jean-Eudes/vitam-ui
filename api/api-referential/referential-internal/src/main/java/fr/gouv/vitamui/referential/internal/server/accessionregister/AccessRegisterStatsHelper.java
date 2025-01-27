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
package fr.gouv.vitamui.referential.internal.server.accessionregister;

import fr.gouv.vitam.common.model.administration.AccessionRegisterDetailModel;
import fr.gouv.vitamui.referential.common.dto.AccessionRegisterStatsDto;

import java.util.List;

public class AccessRegisterStatsHelper {

    private AccessRegisterStatsHelper() {
        throw new UnsupportedOperationException("Utility class !");
    }

    public static AccessionRegisterStatsDto fetchStats(List<AccessionRegisterDetailModel> accessionRegisterDetailModels ) {

        AccessionRegisterStatsDto statsDto = new AccessionRegisterStatsDto();

        Long objectSizes = accessionRegisterDetailModels.parallelStream()
            .map(ardm -> ardm.getObjectSize().getIngested())
            .reduce(0L, Long::sum);

        Long totalObjects = accessionRegisterDetailModels.parallelStream()
            .map(ardm -> ardm.getTotalObjects().getIngested())
            .reduce(0L, Long::sum);

        Long totalUnits = accessionRegisterDetailModels.parallelStream()
            .map(ardm -> ardm.getTotalUnits().getIngested())
            .reduce(0L, Long::sum);

        Long totalObjectsGroups = accessionRegisterDetailModels.parallelStream()
            .map(ardm -> ardm.getTotalObjectsGroups().getIngested())
            .reduce(0L, Long::sum);

        statsDto.setObjectSizes(objectSizes);
        statsDto.setTotalObjects(totalObjects);
        statsDto.setTotalUnits(totalUnits);
        statsDto.setTotalObjectsGroups(totalObjectsGroups);

        return statsDto;
    }

}
