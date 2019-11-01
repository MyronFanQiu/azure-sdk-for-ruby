# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Network::Mgmt::V2019_09_01
  module Models
    #
    # Response for ListRoutesTable associated with the Express Route Cross
    # Connections.
    #
    class ExpressRouteCrossConnectionsRoutesTableSummaryListResult

      include MsRestAzure

      # @return [Array<ExpressRouteCrossConnectionRoutesTableSummary>] A list
      # of the routes table.
      attr_accessor :value

      # @return [String] The URL to get the next set of results.
      attr_accessor :next_link


      #
      # Mapper for ExpressRouteCrossConnectionsRoutesTableSummaryListResult
      # class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ExpressRouteCrossConnectionsRoutesTableSummaryListResult',
          type: {
            name: 'Composite',
            class_name: 'ExpressRouteCrossConnectionsRoutesTableSummaryListResult',
            model_properties: {
              value: {
                client_side_validation: true,
                required: false,
                serialized_name: 'value',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'ExpressRouteCrossConnectionRoutesTableSummaryElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'ExpressRouteCrossConnectionRoutesTableSummary'
                      }
                  }
                }
              },
              next_link: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'nextLink',
                type: {
                  name: 'String'
                }
              }
            }
          }
        }
      end
    end
  end
end
